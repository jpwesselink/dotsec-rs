use base64::Engine as _;
pub use dotenv;
use dotenv::{lines_to_entries, Line, Schema};

mod configuration;
pub use configuration::*;

// --- File helpers ---

pub fn load_file(file: &str) -> Result<String, std::io::Error> {
    std::fs::read_to_string(file)
}

/// Write content to a .sec or schema file with restricted permissions (0600 on Unix).
///
/// Writes via a sibling temp file + atomic rename so a malicious symlink at `path`
/// cannot be used to overwrite the symlink's target. Refuses outright if `path` is
/// already a symlink (preserves user intent — we won't silently replace one).
pub fn write_sec_file(path: &str, content: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::path::{Path, PathBuf};

    let path = Path::new(path);

    // Refuse to write through a symlink. The rename below replaces the symlink itself
    // (not its target) so this check isn't strictly required for safety, but it
    // prevents silently breaking any legitimate symlink the user may have placed.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!("refusing to write through symlink: {}", path.display()).into());
        }
    }

    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or("invalid output path: missing file name")?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(
        ".{}.tmp.{}.{}",
        name.to_string_lossy(),
        std::process::id(),
        nanos,
    ));

    // Drop guard: if we error out before the successful rename, remove the temp file
    // so a crashed write doesn't leak partial plaintext or stale temp files.
    struct TempCleanup(Option<PathBuf>);
    impl Drop for TempCleanup {
        fn drop(&mut self) {
            if let Some(p) = self.0.take() {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    let mut cleanup = TempCleanup(Some(tmp.clone()));

    let mut file = open_temp_write(&tmp)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    drop(file);

    std::fs::rename(&tmp, path)?;
    cleanup.0 = None; // success — keep the renamed file
    Ok(())
}

#[cfg(unix)]
fn open_temp_write(tmp: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp)
}

#[cfg(not(unix))]
fn open_temp_write(tmp: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)
}

// --- Header ---

/// Major version stamped into new `.sec` file headers — derived from the crate's
/// compile-time `CARGO_PKG_VERSION` so it tracks the actual release without manual
/// updates. (`has_header` matches the bare `# dotsec v` prefix so headers stamped
/// by older majors continue to be recognized.)
fn header_major() -> &'static str {
    env!("CARGO_PKG_VERSION").split('.').next().unwrap_or("?")
}

/// Generate the standard dotsec file header (two comment lines + newlines).
pub fn generate_header() -> Vec<Line> {
    vec![
        Line::Comment {
            text: format!("# dotsec v{} — encrypted environment file", header_major()),
        },
        Line::Newline,
        Line::Comment {
            text: "# https://github.com/jpwesselink/dotsec-rs".into(),
        },
        Line::Newline,
    ]
}

/// Check whether parsed lines contain the dotsec header.
pub fn has_header(lines: &[Line]) -> bool {
    lines
        .iter()
        .any(|line| matches!(line, Line::Comment { text } if text.starts_with("# dotsec v")))
}

pub fn parse_content(content: &str) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    Ok(dotenv::parse_dotenv(content)?)
}

// --- Constants ---

const DOTSEC_KEY_NAME: &str = "__DOTSEC_KEY__";
const DOTSEC_V1_NAME: &str = "__DOTSEC__";

// --- Format detection ---

/// Detect whether a .sec file uses v1 (blob) or v2 (per-value) format.
fn detect_format(lines: &[Line]) -> SecFormat {
    for line in lines {
        if let Line::Kv { key, .. } = line {
            if key == DOTSEC_KEY_NAME {
                return SecFormat::V2;
            }
            if key == DOTSEC_V1_NAME {
                return SecFormat::V1;
            }
        }
    }
    SecFormat::None
}

#[derive(Debug, PartialEq)]
enum SecFormat {
    V1,   // Old blob format with __DOTSEC__
    V2,   // New per-value format with __DOTSEC_KEY__
    None, // No encryption markers
}

// --- Encrypt (v2) ---

/// Encrypt in-memory lines and write the result to a .sec file.
///
/// For each entry with `@encrypt`:
///   - Encrypt the value with the DEK → `ENC[base64(commitment||nonce||ciphertext||tag)]`
///
/// The DEK is wrapped by KMS and stored as `__DOTSEC_KEY__="base64(wrapped_dek)"`.
pub async fn encrypt_lines_to_sec(
    lines: &[Line],
    sec_file: &str,
    encryption_engine: &EncryptionEngine,
    schema: Option<&Schema>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut entries = lines_to_entries(lines);

    // Merge schema-owned directives so the encrypt path sees @encrypt/@plaintext even
    // when they live in dotsec.schema rather than inline. Inline directives win on conflict.
    // Also honors a schema-level @default-encrypt (parse_schema attaches file-level
    // directives to entries; we surface them here as a global default).
    if let Some(schema) = schema {
        let schema_default_encrypt: Option<bool> = schema
            .iter()
            .flat_map(|(_, e)| e.directives.iter())
            .find_map(|(name, _)| match name.as_str() {
                "default-encrypt" => Some(true),
                "default-plaintext" => Some(false),
                _ => None,
            });

        for entry in &mut entries {
            // Inline @encrypt/@plaintext on the entry win as a pair — if either is set,
            // skip both from the schema so the user's local override sticks.
            let inline_encryption_override = entry
                .directives
                .iter()
                .any(|(n, _)| n == "encrypt" || n == "plaintext");

            if let Some(schema_entry) = schema.get(&entry.key) {
                for (name, value) in &schema_entry.directives {
                    if name == "default-encrypt" || name == "default-plaintext" {
                        continue;
                    }
                    if (name == "encrypt" || name == "plaintext") && inline_encryption_override {
                        continue;
                    }
                    if !entry.directives.iter().any(|(n, _)| n == name) {
                        entry.directives.push((name.clone(), value.clone()));
                    }
                }
            }
            if !inline_encryption_override
                && !entry
                    .directives
                    .iter()
                    .any(|(n, _)| n == "encrypt" || n == "plaintext")
            {
                if let Some(true) = schema_default_encrypt {
                    entry.directives.push(("encrypt".to_string(), None));
                }
            }
        }
    }

    let (dek, wrapped_dek) = match encryption_engine {
        EncryptionEngine::Aws(opts) => {
            let key_id = opts.key_id.as_deref().ok_or("AWS key_id is required")?;
            let region = opts.region.as_deref();
            match load_existing_dek_aws(sec_file, region).await {
                Ok(pair) => pair,
                Err(e) => {
                    let is_new = is_new_or_no_key(&e);
                    if is_new {
                        aws::generate_data_key(key_id, region).await?
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        EncryptionEngine::Local(opts) => {
            let private_key = crypto::local::load_private_key(sec_file, opts.key_file.as_deref())?;
            let recipient = crypto::local::recipient_from_identity(&private_key)?;
            match load_existing_dek_local(sec_file, &private_key) {
                Ok(pair) => pair,
                Err(e) => {
                    let is_new = is_new_or_no_key(&e);
                    if is_new {
                        let dek = crypto::generate_dek();
                        let wrapped = crypto::local::wrap_dek(&dek, &recipient)?;
                        (dek, wrapped)
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        EncryptionEngine::None => return Err("Encryption engine is required".into()),
    };

    encrypt_with_dek(lines, &entries, &dek, &wrapped_dek, sec_file)
}

#[allow(clippy::borrowed_box)]
fn is_new_or_no_key(e: &Box<dyn std::error::Error>) -> bool {
    let is_new_file = e
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::NotFound);
    let is_no_key = e.to_string().contains("No __DOTSEC_KEY__ found");
    is_new_file || is_no_key
}

/// Inner encryption logic, separated so the caller can zeroize the DEK.
fn encrypt_with_dek(
    lines: &[Line],
    entries: &[dotenv::Entry],
    dek: &[u8],
    wrapped_dek: &[u8],
    sec_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let wrapped_dek_b64 = base64::engine::general_purpose::STANDARD.encode(wrapped_dek);

    let mut sec_lines: Vec<Line> = Vec::new();
    let mut has_key_line = false;

    for line in lines {
        match line {
            Line::Kv {
                key,
                value,
                quote_type,
            } => {
                if key == DOTSEC_KEY_NAME {
                    sec_lines.push(Line::Kv {
                        key: DOTSEC_KEY_NAME.to_string(),
                        value: wrapped_dek_b64.clone(),
                        quote_type: dotenv::QuoteType::Double,
                    });
                    has_key_line = true;
                    continue;
                }

                if key == DOTSEC_V1_NAME {
                    continue;
                }

                let entry = entries.iter().find(|e| e.key == *key);
                let should_encrypt = entry.is_some_and(|e| e.has_directive("encrypt"));

                if should_encrypt {
                    if crypto::is_encrypted_value(value) {
                        sec_lines.push(line.clone());
                    } else {
                        let encrypted = crypto::encrypt_value(value, dek, key)?;
                        sec_lines.push(Line::Kv {
                            key: key.clone(),
                            value: encrypted,
                            quote_type: quote_type.clone(),
                        });
                    }
                } else {
                    sec_lines.push(line.clone());
                }
            }
            Line::Comment { text }
                if text.contains("do not edit the line below, it is managed by dotsec") =>
            {
                continue;
            }
            other => sec_lines.push(other.clone()),
        }
    }

    if !has_key_line {
        let last_is_newline = matches!(sec_lines.last(), Some(Line::Newline));
        if !sec_lines.is_empty() && !last_is_newline {
            sec_lines.push(Line::Newline);
        }
        sec_lines.push(Line::Newline);
        sec_lines.push(Line::Comment {
            text: "# do not edit the line below, it is managed by dotsec".to_string(),
        });
        sec_lines.push(Line::Newline);
        sec_lines.push(Line::Kv {
            key: DOTSEC_KEY_NAME.to_string(),
            value: wrapped_dek_b64,
            quote_type: dotenv::QuoteType::Double,
        });
        sec_lines.push(Line::Newline);
    }

    let output = dotenv::lines_to_string(&sec_lines);
    write_sec_file(sec_file, &output)?;

    Ok(())
}

// --- Decrypt ---

/// Decrypt a .sec file and return resolved lines with plaintext values.
pub async fn decrypt_sec_to_lines(
    sec_file: &str,
    encryption_engine: &EncryptionEngine,
) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    let content = load_file(sec_file)?;
    let lines = dotenv::parse_dotenv(&content)?;

    match detect_format(&lines) {
        SecFormat::V2 => decrypt_v2(sec_file, &lines, encryption_engine).await,
        SecFormat::V1 => decrypt_v1(&lines, encryption_engine).await,
        SecFormat::None => {
            let has_enc_values = lines.iter().any(|l| {
                if let Line::Kv { value: v, .. } = l {
                    crypto::is_encrypted_value(v)
                } else {
                    false
                }
            });
            if has_enc_values {
                return Err(
                    "File contains ENC[...] values but no __DOTSEC_KEY__. File may be corrupted."
                        .into(),
                );
            }
            Ok(lines)
        }
    }
}

/// Decrypt v2 format: unwrap DEK from __DOTSEC_KEY__, then decrypt each ENC[...] value.
async fn decrypt_v2(
    sec_file: &str,
    lines: &[Line],
    encryption_engine: &EncryptionEngine,
) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    let wrapped_dek_b64 =
        dotenv::get_value(lines, DOTSEC_KEY_NAME).ok_or("No __DOTSEC_KEY__ found in .sec file")?;
    let wrapped_dek = base64::engine::general_purpose::STANDARD.decode(&wrapped_dek_b64)?;

    let dek = match encryption_engine {
        EncryptionEngine::Aws(opts) => {
            aws::unwrap_data_key(&wrapped_dek, opts.region.as_deref()).await?
        }
        EncryptionEngine::Local(opts) => {
            let private_key = crypto::local::load_private_key(sec_file, opts.key_file.as_deref())?;
            crypto::local::unwrap_dek(&wrapped_dek, &private_key)?
        }
        EncryptionEngine::None => return Err("Encryption engine is required".into()),
    };

    let mut resolved: Vec<Line> = Vec::new();

    for line in lines {
        match line {
            Line::Kv {
                key,
                value,
                quote_type,
            } => {
                if key == DOTSEC_KEY_NAME {
                    continue;
                }
                if crypto::is_encrypted_value(value) {
                    let plaintext = crypto::decrypt_value(value, &dek, key)?;
                    resolved.push(Line::Kv {
                        key: key.clone(),
                        value: plaintext,
                        quote_type: quote_type.clone(),
                    });
                } else {
                    resolved.push(line.clone());
                }
            }
            Line::Comment { text }
                if text.contains("do not edit the line below, it is managed by dotsec") =>
            {
                continue;
            }
            _ => resolved.push(line.clone()),
        }
    }

    Ok(resolved)
}

/// Decrypt v1 format (legacy blob): decrypt __DOTSEC__ blob, resolve ID references.
async fn decrypt_v1(
    lines: &[Line],
    encryption_engine: &EncryptionEngine,
) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    let dotsec_value =
        dotenv::get_value(lines, DOTSEC_V1_NAME).ok_or("No __DOTSEC__ entry found")?;

    let secrets_json = decrypt_blob_v1(&dotsec_value, encryption_engine).await?;
    let secrets: std::collections::HashMap<String, String> = serde_json::from_str(&secrets_json)?;

    let mut resolved: Vec<Line> = Vec::new();
    let mut skip_dotsec_comment = false;

    for line in lines {
        match line {
            Line::Comment { text }
                if text.contains("do not edit the line below, it is managed by dotsec") =>
            {
                skip_dotsec_comment = true;
                continue;
            }
            Line::Kv {
                key,
                value,
                quote_type,
            } => {
                if key == DOTSEC_V1_NAME {
                    continue;
                }
                if let Some(real_value) = secrets.get(value.as_str()) {
                    resolved.push(Line::Kv {
                        key: key.clone(),
                        value: real_value.clone(),
                        quote_type: quote_type.clone(),
                    });
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

/// Attempt to decrypt a v1 blob (legacy envelopers format).
///
/// This always returns an error directing users to migrate, because v1 blobs
/// are base64-encoded `envelopers::EncryptedRecord` and we no longer bundle the
/// envelopers crate. Users must decrypt with dotsec v4.x first, then re-encrypt
/// with v5.x to migrate to the new per-value encryption format.
async fn decrypt_blob_v1(
    _ciphertext: &str,
    _engine: &EncryptionEngine,
) -> Result<String, Box<dyn std::error::Error>> {
    Err(
        "This .sec file uses the legacy v1 format (single encrypted blob). \
         Please decrypt it with dotsec v4.x first, then re-encrypt with v5.x to migrate \
         to the new per-value encryption format."
            .into(),
    )
}

// --- DEK helpers ---

type DekPair = (zeroize::Zeroizing<Vec<u8>>, Vec<u8>);

/// Try to load and unwrap the existing DEK from a .sec file.
async fn load_existing_dek_aws(
    sec_file: &str,
    region: Option<&str>,
) -> Result<DekPair, Box<dyn std::error::Error>> {
    let content = load_file(sec_file)?;
    let lines = dotenv::parse_dotenv(&content)?;
    let wrapped_b64 =
        dotenv::get_value(&lines, DOTSEC_KEY_NAME).ok_or("No __DOTSEC_KEY__ found")?;
    let wrapped_dek = base64::engine::general_purpose::STANDARD.decode(&wrapped_b64)?;
    let dek = aws::unwrap_data_key(&wrapped_dek, region).await?;
    Ok((dek, wrapped_dek))
}

fn load_existing_dek_local(
    sec_file: &str,
    identity: &str,
) -> Result<DekPair, Box<dyn std::error::Error>> {
    let content = load_file(sec_file)?;
    let lines = dotenv::parse_dotenv(&content)?;
    let wrapped_b64 =
        dotenv::get_value(&lines, DOTSEC_KEY_NAME).ok_or("No __DOTSEC_KEY__ found")?;
    let wrapped_dek = base64::engine::general_purpose::STANDARD.decode(&wrapped_b64)?;
    let dek = crypto::local::unwrap_dek(&wrapped_dek, identity)?;
    Ok((dek, wrapped_dek))
}

// --- Run helpers ---

/// Extract key-value pairs from lines and resolve `${VAR}` interpolation.
///
/// Only double-quoted and unquoted values are interpolated; single-quoted values stay literal.
///
/// Entries marked `@push=…` are excluded by default (they're owned by the push target),
/// unless they also carry `@also-env`. This rule was introduced in v6.0.0. See
/// `Entry::injects_into_env`.
pub fn resolve_env_vars(lines: &[Line]) -> Vec<(String, String)> {
    let entries = lines_to_entries(lines);
    let mut resolved: Vec<(String, String)> = Vec::new();

    for line in lines {
        if let Line::Kv {
            key,
            value,
            quote_type,
        } = line
        {
            if key == DOTSEC_KEY_NAME || key == DOTSEC_V1_NAME {
                continue;
            }
            // Push-only entries (no `@also-env`) are owned by the push target, not the env.
            // `lines_to_entries` already merges file-level @default-* defaults.
            let entry = entries.iter().find(|e| e.key == *key);
            if entry.is_some_and(|e| !e.injects_into_env()) {
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
                if chars.peek() == Some(&'}') {
                    chars.next(); // consume '}'
                    let val = lookup(&var_name, resolved);
                    result.push_str(&val);
                } else {
                    // Unclosed ${ — treat as literal text
                    eprintln!(
                        "warning: unclosed ${{{}}} in value, treating as literal text",
                        var_name
                    );
                    result.push_str("${");
                    result.push_str(&var_name);
                }
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

/// Drop push-only entries (and their preceding directive block) from a parsed line stream.
///
/// Used by `dotsec export` so a `KEY=value` consumed downstream as a `.env` file matches
/// what `dotsec run` would inject — push-only entries stay out of both. Comments, whitespace,
/// and non-push entries are preserved verbatim. See `Entry::injects_into_env`.
pub fn filter_env_injectable_lines(lines: &[Line]) -> Vec<Line> {
    use std::collections::HashSet;

    let entries = lines_to_entries(lines);
    let excluded_keys: HashSet<&str> = entries
        .iter()
        .filter(|e| !e.injects_into_env())
        .map(|e| e.key.as_str())
        .collect();

    if excluded_keys.is_empty() {
        return lines.to_vec();
    }

    let mut out: Vec<Line> = Vec::with_capacity(lines.len());
    let mut pending_directives: Vec<Line> = Vec::new();

    for line in lines {
        match line {
            Line::Directive { .. } => {
                pending_directives.push(line.clone());
            }
            Line::Kv { key, .. } => {
                if excluded_keys.contains(key.as_str()) {
                    // Drop both the kv and its preceding directive block (and trailing newline).
                    pending_directives.clear();
                    if matches!(out.last(), Some(Line::Newline)) {
                        out.pop();
                    }
                } else {
                    out.append(&mut pending_directives);
                    out.push(line.clone());
                }
            }
            Line::Comment { .. } => {
                // Comments terminate directive chains; flush pending.
                out.append(&mut pending_directives);
                out.push(line.clone());
            }
            _ => out.push(line.clone()),
        }
    }

    // Any trailing pending directives without a kv (shouldn't happen in well-formed input,
    // but preserve them rather than silently drop).
    out.append(&mut pending_directives);
    out
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

    // --- write_sec_file ---

    #[test]
    #[cfg(unix)]
    fn write_sec_file_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join("dotsec-test-write-sec");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.sec");

        write_sec_file(path.to_str().unwrap(), "SECRET=hunter2\n").unwrap();

        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- header ---

    #[test]
    fn generate_header_has_two_comment_lines() {
        let header = generate_header();
        let comments: Vec<_> = header
            .iter()
            .filter(|l| matches!(l, Line::Comment { .. }))
            .collect();
        assert_eq!(comments.len(), 2);
    }

    #[test]
    fn generate_header_first_line_contains_current_major() {
        let header = generate_header();
        let expected_major = env!("CARGO_PKG_VERSION").split('.').next().unwrap();
        let expected = format!("dotsec v{}", expected_major);
        assert!(matches!(&header[0], Line::Comment { text } if text.contains(&expected)));
    }

    #[test]
    fn generate_header_second_line_contains_url() {
        let header = generate_header();
        assert!(
            matches!(&header[2], Line::Comment { text } if text.contains("https://github.com/jpwesselink/dotsec-rs"))
        );
    }

    #[test]
    fn has_header_true_when_present() {
        let lines = generate_header();
        assert!(has_header(&lines));
    }

    #[test]
    fn has_header_recognizes_older_majors() {
        // The `# dotsec v` prefix is intentionally version-agnostic so files
        // stamped by older majors (v5, etc.) keep being recognized after we ship a
        // newer major.
        let v5_header = vec![
            Line::Comment {
                text: "# dotsec v5 — encrypted environment file".into(),
            },
            Line::Newline,
        ];
        assert!(has_header(&v5_header));
    }

    #[test]
    fn has_header_false_when_absent() {
        let lines = vec![
            Line::Comment {
                text: "# just a comment".into(),
            },
            Line::Newline,
            Line::Kv {
                key: "FOO".into(),
                value: "bar".into(),
                quote_type: QuoteType::None,
            },
        ];
        assert!(!has_header(&lines));
    }

    #[test]
    fn has_header_matches_any_version() {
        let lines = vec![Line::Comment {
            text: "# dotsec v99 — encrypted environment file".into(),
        }];
        assert!(has_header(&lines));
    }

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
        let resolved = vec![("A".into(), "hello".into()), ("B".into(), "world".into())];
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

    #[test]
    fn interpolate_unclosed_brace_is_literal() {
        let resolved = vec![("A".into(), "val".into())];
        assert_eq!(
            interpolate("path is ${UNCLOSED", &resolved),
            "path is ${UNCLOSED"
        );
    }

    #[test]
    fn interpolate_unclosed_brace_mixed() {
        let resolved = vec![("A".into(), "val".into())];
        assert_eq!(
            interpolate("${A} then ${UNCLOSED", &resolved),
            "val then ${UNCLOSED"
        );
    }

    // --- push-only env exclusion (v6 breaking change) ---

    #[test]
    fn resolve_env_vars_excludes_push_only_entries() {
        // @push without @also-env: belongs to the push target, not the env.
        let lines =
            parse_content("# @push=aws-ssm\nDB_PASSWORD=\"secret\"\n\nFOO=\"bar\"\n").unwrap();
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved, vec![("FOO".into(), "bar".into())]);
        assert!(!resolved.iter().any(|(k, _)| k == "DB_PASSWORD"));
    }

    #[test]
    fn resolve_env_vars_includes_push_when_also_env() {
        // @push + @also-env: opt back in to env injection.
        let lines = parse_content("# @push=aws-ssm @also-env\nDB_PASSWORD=\"secret\"\n").unwrap();
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved, vec![("DB_PASSWORD".into(), "secret".into())]);
    }

    #[test]
    fn filter_env_injectable_lines_drops_push_only_block() {
        let lines = parse_content(
            "# @encrypt\n# @push=aws-ssm\nDB_PASSWORD=\"secret\"\n\n# @encrypt\nAPI_KEY=\"k\"\n",
        )
        .unwrap();
        let filtered = filter_env_injectable_lines(&lines);
        let rendered = dotenv::lines_to_string(&filtered);
        assert!(!rendered.contains("DB_PASSWORD"));
        assert!(!rendered.contains("aws-ssm"));
        assert!(rendered.contains("API_KEY=\"k\""));
    }

    #[test]
    fn filter_env_injectable_lines_keeps_push_with_also_env() {
        let lines = parse_content("# @push=aws-ssm @also-env\nDB_PASSWORD=\"secret\"\n").unwrap();
        let filtered = filter_env_injectable_lines(&lines);
        let rendered = dotenv::lines_to_string(&filtered);
        assert!(rendered.contains("DB_PASSWORD=\"secret\""));
    }

    // --- resolve_env_vars ---

    #[test]
    fn resolve_env_vars_basic() {
        let lines = vec![
            Line::Kv {
                key: "FOO".into(),
                value: "bar".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "BAZ".into(),
                value: "qux".into(),
                quote_type: QuoteType::None,
            },
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
            Line::Kv {
                key: "HOST".into(),
                value: "localhost".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "URL".into(),
                value: "http://${HOST}:3000".into(),
                quote_type: QuoteType::Double,
            },
        ];
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved[1].1, "http://localhost:3000");
    }

    #[test]
    fn resolve_env_vars_single_quote_no_interpolation() {
        let lines = vec![
            Line::Kv {
                key: "HOST".into(),
                value: "localhost".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "LITERAL".into(),
                value: "${HOST}".into(),
                quote_type: QuoteType::Single,
            },
        ];
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved[1].1, "${HOST}");
    }

    #[test]
    fn resolve_env_vars_skips_dotsec_key() {
        let lines = vec![
            Line::Kv {
                key: "FOO".into(),
                value: "bar".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "__DOTSEC_KEY__".into(),
                value: "wrapped".into(),
                quote_type: QuoteType::Double,
            },
        ];
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, "FOO");
    }

    #[test]
    fn resolve_env_vars_skips_dotsec_v1() {
        let lines = vec![
            Line::Kv {
                key: "FOO".into(),
                value: "bar".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "__DOTSEC__".into(),
                value: "blob".into(),
                quote_type: QuoteType::Double,
            },
        ];
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, "FOO");
    }

    // --- format detection ---

    #[test]
    fn detect_v2_format() {
        let lines = vec![
            Line::Kv {
                key: "FOO".into(),
                value: "ENC[abc]".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "__DOTSEC_KEY__".into(),
                value: "wrapped".into(),
                quote_type: QuoteType::Double,
            },
        ];
        assert_eq!(detect_format(&lines), SecFormat::V2);
    }

    #[test]
    fn detect_v1_format() {
        let lines = vec![
            Line::Kv {
                key: "FOO".into(),
                value: "hexid".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "__DOTSEC__".into(),
                value: "blob".into(),
                quote_type: QuoteType::Double,
            },
        ];
        assert_eq!(detect_format(&lines), SecFormat::V1);
    }

    #[test]
    fn detect_no_format() {
        let lines = vec![Line::Kv {
            key: "FOO".into(),
            value: "bar".into(),
            quote_type: QuoteType::Double,
        }];
        assert_eq!(detect_format(&lines), SecFormat::None);
    }

    #[test]
    fn detect_none_with_enc_values_but_no_dotsec_key() {
        // ENC[...] values present but no __DOTSEC_KEY__ or __DOTSEC__ marker
        let lines = vec![
            Line::Kv {
                key: "SECRET".into(),
                value: "ENC[base64data]".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "OTHER".into(),
                value: "ENC[moredata]".into(),
                quote_type: QuoteType::Double,
            },
        ];
        assert_eq!(detect_format(&lines), SecFormat::None);
    }

    #[test]
    fn detect_none_for_empty_lines() {
        let lines: Vec<Line> = vec![];
        assert_eq!(detect_format(&lines), SecFormat::None);
    }

    #[test]
    fn detect_none_for_only_comments_and_newlines() {
        let lines = vec![
            Line::Comment {
                text: "# just a comment".into(),
            },
            Line::Newline,
            Line::Newline,
        ];
        assert_eq!(detect_format(&lines), SecFormat::None);
    }

    #[test]
    fn detect_v2_takes_priority_over_enc_values() {
        // Both ENC values and __DOTSEC_KEY__ present → V2
        let lines = vec![
            Line::Kv {
                key: "SECRET".into(),
                value: "ENC[data]".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "__DOTSEC_KEY__".into(),
                value: "wrapped_key".into(),
                quote_type: QuoteType::Double,
            },
        ];
        assert_eq!(detect_format(&lines), SecFormat::V2);
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
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "SECRET".into(),
                value: "shhh".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "PUBLIC".into(),
                value: "visible".into(),
                quote_type: QuoteType::None,
            },
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
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "A".into(),
                value: "ab".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "B".into(),
                value: "abcdef".into(),
                quote_type: QuoteType::Double,
            },
        ];
        let env_vars = vec![("A".into(), "ab".into()), ("B".into(), "abcdef".into())];
        let secrets = collect_secret_values(&lines, &env_vars);
        assert_eq!(secrets, vec!["abcdef", "ab"]);
    }

    #[test]
    fn collect_secrets_skips_empty_values() {
        let lines = vec![
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "EMPTY".into(),
                value: "".into(),
                quote_type: QuoteType::Double,
            },
        ];
        let env_vars = vec![("EMPTY".into(), "".into())];
        let secrets = collect_secret_values(&lines, &env_vars);
        assert!(secrets.is_empty());
    }

    // --- detect_format tests ---

    #[test]
    fn detect_enc_values_without_key_is_none() {
        let lines = vec![Line::Kv {
            key: "SECRET".into(),
            value: "ENC[base64data]".into(),
            quote_type: QuoteType::Double,
        }];
        assert!(matches!(detect_format(&lines), SecFormat::None));
    }

    #[test]
    fn detect_empty_lines_is_none() {
        let lines: Vec<Line> = vec![];
        assert!(matches!(detect_format(&lines), SecFormat::None));
    }

    #[test]
    fn detect_dotsec_key_is_v2() {
        let lines = vec![
            Line::Kv {
                key: "__DOTSEC_KEY__".into(),
                value: "wrapped_dek".into(),
                quote_type: QuoteType::Double,
            },
            Line::Kv {
                key: "SECRET".into(),
                value: "ENC[data]".into(),
                quote_type: QuoteType::Double,
            },
        ];
        assert!(matches!(detect_format(&lines), SecFormat::V2));
    }

    // --- Plaintext .sec roundtrip tests ---

    #[test]
    fn plaintext_sec_roundtrip() {
        // Create lines with @default-plaintext + some Kv entries
        let lines = vec![
            Line::Directive {
                name: "default-plaintext".into(),
                value: None,
            },
            Line::Newline,
            Line::Newline,
            Line::Kv {
                key: "FOO".into(),
                value: "bar".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "PORT".into(),
                value: "3000".into(),
                quote_type: QuoteType::None,
            },
            Line::Newline,
        ];

        // Serialize to string
        let content = dotenv::lines_to_string(&lines);

        // Parse back and verify values match
        let reparsed = dotenv::parse_dotenv(&content).unwrap();
        let entries = dotenv::lines_to_entries(&reparsed);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "FOO");
        assert_eq!(entries[0].value, "bar");
        assert_eq!(entries[1].key, "PORT");
        assert_eq!(entries[1].value, "3000");
    }

    #[test]
    fn detect_format_none_for_plaintext_file() {
        // A file with no ENC[...] values and no __DOTSEC_KEY__
        let lines = vec![
            Line::Directive {
                name: "default-plaintext".into(),
                value: None,
            },
            Line::Newline,
            Line::Newline,
            Line::Kv {
                key: "FOO".into(),
                value: "bar".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "PORT".into(),
                value: "3000".into(),
                quote_type: QuoteType::None,
            },
            Line::Newline,
        ];
        assert_eq!(detect_format(&lines), SecFormat::None);
    }

    #[test]
    fn sec_format_none_with_enc_values_detected() {
        // A file with ENC[...] values but NO __DOTSEC_KEY__
        let lines = vec![
            Line::Kv {
                key: "SECRET".into(),
                value: "ENC[base64data]".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "OTHER".into(),
                value: "ENC[moredata]".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];

        // detect_format returns None (no __DOTSEC_KEY__)
        assert_eq!(detect_format(&lines), SecFormat::None);

        // But we can detect the ENC values are present, which should be an error condition
        let has_enc_values = lines.iter().any(|l| {
            if let Line::Kv { value: v, .. } = l {
                crypto::is_encrypted_value(v)
            } else {
                false
            }
        });
        assert!(has_enc_values, "ENC values should be detected");

        // This combination (ENC values without __DOTSEC_KEY__) indicates a corrupted file
    }

    // --- redact (extended) ---

    #[test]
    fn redact_across_full_line() {
        let secrets = vec!["entire-line-is-secret".to_string()];
        let redacted = redact("entire-line-is-secret", &secrets);
        assert_eq!(
            redacted,
            "*".repeat("entire-line-is-secret".len()),
            "a secret that spans the full line should be fully masked"
        );
    }

    #[test]
    fn redact_preserves_non_secret_content() {
        let secrets = vec!["hidden".to_string()];
        let result = redact("prefix hidden suffix", &secrets);
        assert_eq!(result, "prefix ****** suffix");
        assert!(result.contains("prefix"));
        assert!(result.contains("suffix"));
        assert!(!result.contains("hidden"));
    }

    #[test]
    fn redact_empty_secrets_list() {
        let secrets: Vec<String> = vec![];
        let line = "nothing changes here";
        assert_eq!(redact(line, &secrets), line);
    }

    #[test]
    fn collect_and_redact_integration() {
        // Parse a .sec-style string with @encrypt directive
        let sec_content =
            "# @encrypt\nDB_PASSWORD=\"super-secret-pw\"\nPUBLIC_URL=http://example.com\n";
        let lines = dotenv::parse_dotenv(sec_content).unwrap();

        // Resolve env vars
        let env_vars = resolve_env_vars(&lines);
        assert_eq!(env_vars.len(), 2);

        // Collect secret values (only @encrypt entries)
        let secrets = collect_secret_values(&lines, &env_vars);
        assert_eq!(secrets, vec!["super-secret-pw"]);

        // Redact a line containing one of the secret values
        let output_line = "connecting to DB with password super-secret-pw ...";
        let redacted = redact(output_line, &secrets);
        assert!(
            !redacted.contains("super-secret-pw"),
            "secret value should be masked"
        );
        assert!(
            redacted.contains("***************"),
            "masked value should be asterisks of same length"
        );
        assert!(
            redacted.contains("connecting to DB with password"),
            "non-secret text should be preserved"
        );
    }

    // --- resolve_env_vars (extended for run --using env) ---

    #[test]
    fn resolve_env_vars_from_plain_env() {
        let env_content = "APP_NAME=myapp\nPORT=8080\nDEBUG=true\n";
        let lines = dotenv::parse_dotenv(env_content).unwrap();
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved.len(), 3);
        assert_eq!(resolved[0], ("APP_NAME".into(), "myapp".into()));
        assert_eq!(resolved[1], ("PORT".into(), "8080".into()));
        assert_eq!(resolved[2], ("DEBUG".into(), "true".into()));
    }

    #[test]
    fn resolve_env_vars_with_interpolation() {
        let env_content = "BASE=\"http://localhost\"\nURL=\"${BASE}/api\"\n";
        let lines = dotenv::parse_dotenv(env_content).unwrap();
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0], ("BASE".into(), "http://localhost".into()));
        assert_eq!(resolved[1], ("URL".into(), "http://localhost/api".into()));
    }

    #[test]
    fn resolve_env_vars_single_quotes_no_interpolation() {
        let env_content = "HOST=\"localhost\"\nLITERAL='${HOST}/path'\n";
        let lines = dotenv::parse_dotenv(env_content).unwrap();
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0], ("HOST".into(), "localhost".into()));
        assert_eq!(
            resolved[1],
            ("LITERAL".into(), "${HOST}/path".into()),
            "single-quoted values should not interpolate"
        );
    }

    #[test]
    fn plaintext_lines_to_string_roundtrip_with_directives() {
        let source =
            "# @default-plaintext\n\n# @type=string\nFOO=\"hello\"\n\n# @type=number\nPORT=3000\n";
        let lines = dotenv::parse_dotenv(source).unwrap();
        let output = dotenv::lines_to_string(&lines);
        assert_eq!(output, source);

        // Re-parse and validate entries
        let reparsed = dotenv::parse_dotenv(&output).unwrap();
        let entries = dotenv::lines_to_entries(&reparsed);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "FOO");
        assert_eq!(entries[0].value, "hello");
        assert!(
            !entries[0].has_directive("encrypt"),
            "plaintext default should not add encrypt"
        );
    }

    // --- local encryption integration ---

    #[tokio::test]
    async fn local_encrypt_decrypt_roundtrip() {
        let dir = std::env::temp_dir().join("dotsec-test-local-roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();

        let (identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();

        let lines = vec![
            Line::Directive {
                name: "provider".to_string(),
                value: Some("local".to_string()),
            },
            Line::Newline,
            Line::Directive {
                name: "encrypt".to_string(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "SECRET".into(),
                value: "hunter2".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "PUBLIC".into(),
                value: "hello".into(),
                quote_type: QuoteType::None,
            },
            Line::Newline,
        ];

        let engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(key_file.clone()),
        });

        encrypt_lines_to_sec(&lines, &sec_file, &engine, None)
            .await
            .unwrap();

        let content = std::fs::read_to_string(&sec_file).unwrap();
        assert!(
            content.contains("ENC["),
            "encrypted value should contain ENC[...]"
        );
        assert!(
            content.contains("__DOTSEC_KEY__"),
            "should contain wrapped DEK"
        );
        assert!(!content.contains("hunter2"), "plaintext should not appear");

        let decrypted = decrypt_sec_to_lines(&sec_file, &engine).await.unwrap();
        let secret_val = decrypted.iter().find_map(|l| {
            if let Line::Kv { key, value, .. } = l {
                if key == "SECRET" {
                    Some(value.clone())
                } else {
                    None
                }
            } else {
                None
            }
        });
        assert_eq!(secret_val.as_deref(), Some("hunter2"));

        let public_val = decrypted.iter().find_map(|l| {
            if let Line::Kv { key, value, .. } = l {
                if key == "PUBLIC" {
                    Some(value.clone())
                } else {
                    None
                }
            } else {
                None
            }
        });
        assert_eq!(public_val.as_deref(), Some("hello"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn local_decrypt_with_wrong_key_fails() {
        let dir = std::env::temp_dir().join("dotsec-test-local-wrong-key");
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();
        let wrong_key_file = dir.join("wrong.sec.key").to_string_lossy().to_string();

        let (identity, _) = crypto::local::generate_keypair();
        let (wrong_identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();
        std::fs::write(&wrong_key_file, &wrong_identity).unwrap();

        let lines = vec![
            Line::Directive {
                name: "encrypt".to_string(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "SECRET".into(),
                value: "hunter2".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];

        let engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(key_file),
        });

        encrypt_lines_to_sec(&lines, &sec_file, &engine, None)
            .await
            .unwrap();

        let wrong_engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(wrong_key_file),
        });
        let result = decrypt_sec_to_lines(&sec_file, &wrong_engine).await;
        assert!(result.is_err(), "decrypting with wrong key should fail");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn local_decrypt_discovers_sibling_key_file() {
        let dir = std::env::temp_dir().join("dotsec-test-local-discovery");
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();

        let (identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();

        let lines = vec![
            Line::Directive {
                name: "encrypt".to_string(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "SECRET".into(),
                value: "hunter2".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];

        let encrypt_engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(key_file.clone()),
        });
        encrypt_lines_to_sec(&lines, &sec_file, &encrypt_engine, None)
            .await
            .unwrap();

        // Decrypt with key_file: None — must auto-discover <sec>.key.
        let decrypt_engine = EncryptionEngine::Local(LocalEncryptionOptions { key_file: None });
        let decrypted = decrypt_sec_to_lines(&sec_file, &decrypt_engine)
            .await
            .unwrap();
        let secret_val = decrypted.iter().find_map(|l| {
            if let Line::Kv { key, value, .. } = l {
                if key == "SECRET" {
                    Some(value.clone())
                } else {
                    None
                }
            } else {
                None
            }
        });
        assert_eq!(secret_val.as_deref(), Some("hunter2"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn schema_owned_encrypt_directive_still_encrypts() {
        // Regression: when @encrypt lives in dotsec.schema (not inline in .sec),
        // encrypt_lines_to_sec must still encrypt the value. Pre-fix this silently wrote
        // plaintext, leaking secrets on rewrite paths (format, extract-schema, remove-directives).
        let dir = std::env::temp_dir().join("dotsec-test-schema-encrypt");
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();
        let (identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();

        // Build a schema where @encrypt is schema-owned for DB_PASSWORD.
        let schema = dotenv::parse_schema("# @encrypt\nDB_PASSWORD\n").unwrap();

        // .sec lines with no inline @encrypt directive.
        let lines = vec![
            Line::Kv {
                key: "DB_PASSWORD".into(),
                value: "secret123".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];

        let engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(key_file),
        });
        encrypt_lines_to_sec(&lines, &sec_file, &engine, Some(&schema))
            .await
            .unwrap();

        let on_disk = std::fs::read_to_string(&sec_file).unwrap();
        assert!(
            on_disk.contains("ENC["),
            "schema-owned @encrypt should still encrypt: {}",
            on_disk
        );
        assert!(
            !on_disk.contains("secret123"),
            "plaintext leaked to disk: {}",
            on_disk
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn schema_default_encrypt_still_encrypts() {
        // Regression: when @default-encrypt lives in dotsec.schema (file-level), all entries
        // without explicit @plaintext should still be encrypted.
        let dir = std::env::temp_dir().join("dotsec-test-schema-default-encrypt");
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();
        let (identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();

        let schema = dotenv::parse_schema("# @default-encrypt\n\nDB_PASSWORD\n").unwrap();

        let lines = vec![
            Line::Kv {
                key: "DB_PASSWORD".into(),
                value: "secret123".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];

        let engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(key_file),
        });
        encrypt_lines_to_sec(&lines, &sec_file, &engine, Some(&schema))
            .await
            .unwrap();

        let on_disk = std::fs::read_to_string(&sec_file).unwrap();
        assert!(
            on_disk.contains("ENC["),
            "schema @default-encrypt should encrypt: {}",
            on_disk
        );
        assert!(
            !on_disk.contains("secret123"),
            "plaintext leaked: {}",
            on_disk
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn inline_plaintext_overrides_schema_encrypt() {
        // Inline @plaintext on an entry must win over a schema-owned @encrypt for the same key.
        let dir = std::env::temp_dir().join("dotsec-test-inline-plaintext-wins");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();
        let (identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();

        let schema = dotenv::parse_schema("# @encrypt\nFOO\n").unwrap();

        let lines = vec![
            Line::Directive {
                name: "plaintext".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "FOO".into(),
                value: "hello".into(),
                quote_type: QuoteType::None,
            },
            Line::Newline,
        ];

        let engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(key_file),
        });
        encrypt_lines_to_sec(&lines, &sec_file, &engine, Some(&schema))
            .await
            .unwrap();

        let on_disk = std::fs::read_to_string(&sec_file).unwrap();
        assert!(
            on_disk.contains("FOO=hello"),
            "inline @plaintext should keep value plain: {}",
            on_disk
        );
        assert!(
            !on_disk.contains("FOO=ENC["),
            "inline @plaintext was ignored: {}",
            on_disk
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- write_sec_file safety ---

    #[test]
    #[cfg(unix)]
    fn write_sec_file_refuses_to_follow_symlink_to_existing_file() {
        // Layout: .sec.key is a symlink to ~/.ssh/id_rsa (mocked here as `target`).
        // write_sec_file(".sec.key", "new content") must NOT overwrite target.
        let dir = std::env::temp_dir().join("dotsec-test-symlink-refuse");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        let link = dir.join("link.sec");
        std::fs::write(&target, "do-not-touch").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = write_sec_file(link.to_str().unwrap(), "new content");
        assert!(result.is_err(), "writing through symlink must error");
        assert!(
            result.unwrap_err().to_string().contains("symlink"),
            "error should mention symlink"
        );

        let target_after = std::fs::read_to_string(&target).unwrap();
        assert_eq!(target_after, "do-not-touch", "symlink target was clobbered");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_sec_file_creates_new_file_atomically() {
        let dir = std::env::temp_dir().join("dotsec-test-write-create");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fresh.sec");

        write_sec_file(path.to_str().unwrap(), "hello").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello");

        // No stray temp files left behind in the directory.
        let strays: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                n.starts_with(".fresh.sec.tmp.")
            })
            .collect();
        assert!(strays.is_empty(), "leftover temp files: {:?}", strays);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_sec_file_overwrites_existing_regular_file() {
        let dir = std::env::temp_dir().join("dotsec-test-write-overwrite");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("existing.sec");
        std::fs::write(&path, "old").unwrap();

        write_sec_file(path.to_str().unwrap(), "new").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");

        // Confirm we replaced the file (not the symlink-target attack — the original
        // wasn't a symlink, so direct overwrite is the correct behavior).
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert!(meta.file_type().is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
