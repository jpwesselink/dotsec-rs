pub use dotenv;
use dotenv::{lines_to_entries, Line};
use std::collections::HashMap;

mod configuration;
pub use configuration::*;

// --- File helpers ---

pub fn load_file(file: &str) -> Result<String, std::io::Error> {
    std::fs::read_to_string(file)
}

pub fn parse_content(content: &str) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    Ok(dotenv::parse_dotenv(content)?)
}

// --- Encrypt ---

/// Encrypt in-memory lines and write the result to a .sec file.
///
/// For each entry with `@encrypt`:
///   - Generate a random opaque ID
///   - Replace the value with that ID in the output lines
///   - Store {id: real_value} in a hashmap
///
/// The hashmap is serialized to JSON, encrypted via the encryption engine,
/// and appended as `__DOTSEC__="<base64 blob>"`.
pub async fn encrypt_lines_to_sec(
    lines: &[Line],
    sec_file: &str,
    encryption_engine: &EncryptionEngine,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = lines_to_entries(lines);

    // Try to load existing .sec file to reuse IDs for unchanged values
    let old_value_to_id: HashMap<String, String> =
        match load_existing_secrets(sec_file, encryption_engine).await {
            Ok(old_secrets) => old_secrets
                .into_iter()
                .map(|(id, value)| (value, id))
                .collect(),
            Err(_) => HashMap::new(),
        };

    let mut secrets: HashMap<String, String> = HashMap::new();
    let mut sec_lines: Vec<Line> = Vec::new();

    for line in lines {
        match line {
            Line::Kv(key, value, quote_type) => {
                let entry = entries.iter().find(|e| e.key == *key);
                let should_encrypt = entry.is_some_and(|e| e.has_directive("encrypt"));

                if should_encrypt {
                    let id = match old_value_to_id.get(value) {
                        Some(existing_id) => existing_id.clone(),
                        None => generate_random_id(),
                    };
                    secrets.insert(id.clone(), value.clone());
                    sec_lines.push(Line::Kv(key.clone(), id, quote_type.clone()));
                } else {
                    sec_lines.push(line.clone());
                }
            }
            other => sec_lines.push(other.clone()),
        }
    }

    if !secrets.is_empty() {
        let secrets_json = serde_json::to_string(&secrets)?;
        let encrypted_blob = encrypt_blob(&secrets_json, encryption_engine).await?;

        sec_lines.push(Line::Newline);
        sec_lines.push(Line::Comment(
            "# do not edit the line below, it is managed by dotsec".to_string(),
        ));
        sec_lines.push(Line::Newline);
        sec_lines.push(Line::Kv(
            "__DOTSEC__".to_string(),
            encrypted_blob,
            dotenv::QuoteType::Double,
        ));
        sec_lines.push(Line::Newline);
    }

    let output = dotenv::lines_to_string(&sec_lines);
    std::fs::write(sec_file, output)?;

    Ok(())
}

// --- Decrypt ---

/// Decrypt a .sec file and return resolved lines (for injecting into a process).
pub async fn decrypt_sec_to_lines(
    sec_file: &str,
    encryption_engine: &EncryptionEngine,
) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    let content = load_file(sec_file)?;
    let lines = dotenv::parse_dotenv(&content)?;

    // If there's no __DOTSEC__ blob, nothing is encrypted — return lines as-is
    let dotsec_value = match dotenv::get_value(&lines, "__DOTSEC__") {
        Some(v) => v,
        None => return Ok(lines),
    };

    let secrets_json = decrypt_blob(&dotsec_value, encryption_engine).await?;
    let secrets: HashMap<String, String> = serde_json::from_str(&secrets_json)?;

    let mut resolved: Vec<Line> = Vec::new();
    let mut skip_dotsec_comment = false;

    for line in &lines {
        match line {
            Line::Comment(c)
                if c.contains("do not edit the line below, it is managed by dotsec") =>
            {
                skip_dotsec_comment = true;
                continue;
            }
            Line::Kv(key, value, quote_type) => {
                if key == "__DOTSEC__" {
                    continue;
                }
                if let Some(real_value) = secrets.get(value) {
                    resolved.push(Line::Kv(
                        key.clone(),
                        real_value.clone(),
                        quote_type.clone(),
                    ));
                } else {
                    resolved.push(line.clone());
                }
            }
            Line::Newline if skip_dotsec_comment => {
                skip_dotsec_comment = false;
                continue;
            }
            _ => resolved.push(line.clone()),
        }
    }

    Ok(resolved)
}

// --- Encryption plumbing ---

async fn encrypt_blob(
    plaintext: &str,
    engine: &EncryptionEngine,
) -> Result<String, Box<dyn std::error::Error>> {
    match engine {
        EncryptionEngine::Aws(opts) => {
            let key_id = opts.key_id.as_deref().ok_or("AWS key_id is required")?;
            let region = opts.region.as_deref();
            aws::encrypt_raw(plaintext, key_id, region).await
        }
        EncryptionEngine::None => Err("Encryption engine is required".into()),
    }
}

async fn decrypt_blob(
    ciphertext: &str,
    engine: &EncryptionEngine,
) -> Result<String, Box<dyn std::error::Error>> {
    match engine {
        EncryptionEngine::Aws(opts) => {
            let key_id = opts.key_id.as_deref().ok_or("AWS key_id is required")?;
            let region = opts.region.as_deref();
            aws::decrypt_raw(ciphertext, key_id, region).await
        }
        EncryptionEngine::None => Err("Encryption engine is required".into()),
    }
}

/// Load and decrypt the existing secrets map from a .sec file.
async fn load_existing_secrets(
    sec_file: &str,
    encryption_engine: &EncryptionEngine,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let content = load_file(sec_file)?;
    let lines = dotenv::parse_dotenv(&content)?;
    let dotsec_value =
        dotenv::get_value(&lines, "__DOTSEC__").ok_or("No __DOTSEC__ entry found")?;
    let secrets_json = decrypt_blob(&dotsec_value, encryption_engine).await?;
    let secrets: HashMap<String, String> = serde_json::from_str(&secrets_json)?;
    Ok(secrets)
}

/// Generate a cryptographically random hex ID (32 bytes = 64 hex chars).
fn generate_random_id() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

// --- Run helpers ---

/// Extract key-value pairs from lines and resolve `${VAR}` interpolation.
/// Only double-quoted and unquoted values are interpolated; single-quoted values stay literal.
pub fn resolve_env_vars(lines: &[Line]) -> Vec<(String, String)> {
    let mut resolved: Vec<(String, String)> = Vec::new();

    for line in lines {
        if let Line::Kv(key, value, quote_type) = line {
            if key == "__DOTSEC__" {
                continue;
            }
            let final_value = match quote_type {
                dotenv::QuoteType::Single => value.clone(),
                _ => interpolate(value, &resolved),
            };
            resolved.push((key.clone(), final_value));
        }
    }

    resolved
}

/// Replace `${VAR}` and `$VAR` patterns with values from the resolved map.
fn interpolate(value: &str, resolved: &[(String, String)]) -> String {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' {
            if chars.peek() == Some(&'{') {
                chars.next(); // consume '{'
                let mut var_name = String::new();
                while chars.peek().is_some_and(|c| *c != '}') {
                    var_name.push(chars.next().unwrap());
                }
                chars.next(); // consume '}'
                let val = lookup(&var_name, resolved);
                result.push_str(&val);
            } else if chars
                .peek()
                .is_some_and(|c| c.is_ascii_alphabetic() || *c == '_')
            {
                let mut var_name = String::new();
                while chars
                    .peek()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
                {
                    var_name.push(chars.next().unwrap());
                }
                let val = lookup(&var_name, resolved);
                result.push_str(&val);
            } else {
                result.push('$');
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Look up a variable from the resolved list, falling back to the process environment.
fn lookup(name: &str, resolved: &[(String, String)]) -> String {
    for (k, v) in resolved.iter().rev() {
        if k == name {
            return v.clone();
        }
    }
    std::env::var(name).unwrap_or_default()
}

/// Collect the values of entries marked `@encrypt` from the resolved env vars.
pub fn collect_secret_values(lines: &[Line], env_vars: &[(String, String)]) -> Vec<String> {
    let entries = lines_to_entries(lines);
    let mut secrets = Vec::new();
    for entry in &entries {
        if entry.has_directive("encrypt") {
            if let Some((_, val)) = env_vars.iter().find(|(k, _)| k == &entry.key) {
                if !val.is_empty() {
                    secrets.push(val.clone());
                }
            }
        }
    }
    // Sort longest first so we replace longer matches before shorter substrings
    secrets.sort_by_key(|b| std::cmp::Reverse(b.len()));
    secrets
}

/// Replace all occurrences of secret values in a string with asterisks.
pub fn redact(line: &str, secrets: &[String]) -> String {
    let mut result = line.to_string();
    for secret in secrets {
        result = result.replace(secret, &"*".repeat(secret.len()));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use dotenv::{Line, QuoteType};

    // --- interpolate ---

    #[test]
    fn interpolate_braced_var() {
        let resolved = vec![("FOO".into(), "100".into())];
        assert_eq!(interpolate("val is ${FOO}", &resolved), "val is 100");
    }

    #[test]
    fn interpolate_unbraced_var() {
        let resolved = vec![("FOO".into(), "100".into())];
        assert_eq!(interpolate("val is $FOO!", &resolved), "val is 100!");
    }

    #[test]
    fn interpolate_missing_var_yields_empty() {
        let resolved: Vec<(String, String)> = vec![];
        assert_eq!(interpolate("${NOPE}", &resolved), "");
    }

    #[test]
    fn interpolate_multiple_vars() {
        let resolved = vec![
            ("A".into(), "hello".into()),
            ("B".into(), "world".into()),
        ];
        assert_eq!(interpolate("${A} ${B}", &resolved), "hello world");
    }

    #[test]
    fn interpolate_bare_dollar_preserved() {
        let resolved: Vec<(String, String)> = vec![];
        assert_eq!(interpolate("price is $5", &resolved), "price is $5");
    }

    #[test]
    fn interpolate_no_vars() {
        let resolved: Vec<(String, String)> = vec![];
        assert_eq!(interpolate("plain text", &resolved), "plain text");
    }

    // --- resolve_env_vars ---

    #[test]
    fn resolve_env_vars_basic() {
        let lines = vec![
            Line::Kv("FOO".into(), "bar".into(), QuoteType::Double),
            Line::Newline,
            Line::Kv("BAZ".into(), "qux".into(), QuoteType::None),
        ];
        let resolved = resolve_env_vars(&lines);
        assert_eq!(
            resolved,
            vec![("FOO".into(), "bar".into()), ("BAZ".into(), "qux".into()),]
        );
    }

    #[test]
    fn resolve_env_vars_interpolation() {
        let lines = vec![
            Line::Kv("HOST".into(), "localhost".into(), QuoteType::Double),
            Line::Newline,
            Line::Kv(
                "URL".into(),
                "http://${HOST}:3000".into(),
                QuoteType::Double,
            ),
        ];
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved[1].1, "http://localhost:3000");
    }

    #[test]
    fn resolve_env_vars_single_quote_no_interpolation() {
        let lines = vec![
            Line::Kv("HOST".into(), "localhost".into(), QuoteType::Double),
            Line::Newline,
            Line::Kv("LITERAL".into(), "${HOST}".into(), QuoteType::Single),
        ];
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved[1].1, "${HOST}");
    }

    #[test]
    fn resolve_env_vars_skips_dotsec_entry() {
        let lines = vec![
            Line::Kv("FOO".into(), "bar".into(), QuoteType::Double),
            Line::Newline,
            Line::Kv("__DOTSEC__".into(), "blob".into(), QuoteType::Double),
        ];
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, "FOO");
    }

    // --- redact ---

    #[test]
    fn redact_replaces_secrets() {
        let secrets = vec!["s3cret".to_string()];
        assert_eq!(
            redact("my password is s3cret", &secrets),
            "my password is ******"
        );
    }

    #[test]
    fn redact_multiple_secrets() {
        let secrets = vec!["longersecret".to_string(), "short".to_string()];
        assert_eq!(
            redact("short and longersecret here", &secrets),
            "***** and ************ here"
        );
    }

    #[test]
    fn redact_no_secrets() {
        let secrets: Vec<String> = vec![];
        assert_eq!(redact("nothing to hide", &secrets), "nothing to hide");
    }

    #[test]
    fn redact_secret_appearing_multiple_times() {
        let secrets = vec!["tok".to_string()];
        assert_eq!(redact("tok and tok again", &secrets), "*** and *** again");
    }

    // --- collect_secret_values ---

    #[test]
    fn collect_secrets_only_encrypted_entries() {
        let lines = vec![
            Line::Directive("encrypt".into(), None),
            Line::Newline,
            Line::Kv("SECRET".into(), "shhh".into(), QuoteType::Double),
            Line::Newline,
            Line::Kv("PUBLIC".into(), "visible".into(), QuoteType::None),
        ];
        let env_vars = vec![
            ("SECRET".into(), "shhh".into()),
            ("PUBLIC".into(), "visible".into()),
        ];
        let secrets = collect_secret_values(&lines, &env_vars);
        assert_eq!(secrets, vec!["shhh"]);
    }

    #[test]
    fn collect_secrets_sorted_longest_first() {
        let lines = vec![
            Line::Directive("encrypt".into(), None),
            Line::Newline,
            Line::Kv("A".into(), "ab".into(), QuoteType::Double),
            Line::Newline,
            Line::Directive("encrypt".into(), None),
            Line::Newline,
            Line::Kv("B".into(), "abcdef".into(), QuoteType::Double),
        ];
        let env_vars = vec![
            ("A".into(), "ab".into()),
            ("B".into(), "abcdef".into()),
        ];
        let secrets = collect_secret_values(&lines, &env_vars);
        assert_eq!(secrets, vec!["abcdef", "ab"]);
    }

    #[test]
    fn collect_secrets_skips_empty_values() {
        let lines = vec![
            Line::Directive("encrypt".into(), None),
            Line::Newline,
            Line::Kv("EMPTY".into(), "".into(), QuoteType::Double),
        ];
        let env_vars = vec![("EMPTY".into(), "".into())];
        let secrets = collect_secret_values(&lines, &env_vars);
        assert!(secrets.is_empty());
    }
}
