use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;
use std::collections::HashMap;
pub mod types;
#[derive(Parser)]
#[grammar = "dotenv.pest"]
struct DotenvLineParser;
pub use types::{DiffItem, Entry, FileConfig, Line, PushTarget, QuoteType, SecretsManagerOptions, SsmOptions, ValidationError, VarType};

pub fn lines_to_string(lines: &[Line]) -> String {
    let mut output = String::new();
    let mut in_directive = false;

    for x in lines {
        match x {
            Line::Directive(name, value) => {
                if in_directive {
                    // Continue on same line
                    output.push(' ');
                } else {
                    output.push_str("# ");
                    in_directive = true;
                }
                match value {
                    Some(v) => output.push_str(&format!("@{}={}", name, v)),
                    None => output.push_str(&format!("@{}", name)),
                }
            }
            other => {
                in_directive = false;
                match other {
                    Line::Comment(comment) => output.push_str(comment),
                    Line::Whitespace(ws) => output.push_str(ws),
                    Line::Kv(k, v, quote_type) => match quote_type {
                        QuoteType::Single => output.push_str(&format!("{}='{}'", k, v)),
                        QuoteType::Double => output.push_str(&format!("{}=\"{}\"", k, v)),
                        QuoteType::Backtick => output.push_str(&format!("{}=`{}`", k, v)),
                        QuoteType::None => output.push_str(&format!("{}={}", k, v)),
                    },
                    Line::Newline => output.push('\n'),
                    _ => {}
                }
            }
        }
    }
    output
}

/// Extract file-level config directives from parsed lines.
/// Only looks at directives before the first KV line.
pub fn extract_file_config(lines: &[Line]) -> FileConfig {
    let mut config = FileConfig::default();

    for line in lines {
        match line {
            Line::Kv(_, _, _) => break, // stop at first variable
            Line::Directive(name, value) => match name.as_str() {
                "provider" => config.provider = value.clone(),
                "key-id" => config.key_id = value.clone(),
                "region" => config.region = value.clone(),
                "default-encrypt" => config.default_encrypt = Some(true),
                "default-plaintext" => config.default_encrypt = Some(false),
                _ => {}
            },
            _ => {}
        }
    }

    config
}

/// Group lines into entries: each Kv gets associated with any directives that precede it.
/// Non-kv lines (comments, whitespace, newlines) that aren't directives are returned as-is
/// in a parallel structure for roundtripping.
pub fn lines_to_entries(lines: &[Line]) -> Vec<Entry> {
    // Detect file-level default encryption directive
    let mut default_encrypt: Option<bool> = None;
    for line in lines {
        match line {
            Line::Directive(name, _) if name == "default-encrypt" => {
                default_encrypt = Some(true);
                break;
            }
            Line::Directive(name, _) if name == "default-plaintext" => {
                default_encrypt = Some(false);
                break;
            }
            _ => {}
        }
    }

    let mut entries = Vec::new();
    let mut pending_directives: Vec<(String, Option<String>)> = Vec::new();

    for line in lines {
        match line {
            Line::Directive(name, value) => {
                // Skip file-level config directives from being attached to entries
                if matches!(name.as_str(), "default-encrypt" | "default-plaintext" | "provider" | "key-id" | "region") {
                    continue;
                }
                pending_directives.push((name.clone(), value.clone()));
            }
            Line::Kv(k, v, qt) => {
                let mut directives = std::mem::take(&mut pending_directives);

                // Apply file-level default if entry has no explicit encrypt/plaintext
                let has_explicit = directives.iter().any(|(n, _)| n == "encrypt" || n == "plaintext");
                if !has_explicit {
                    if let Some(true) = default_encrypt {
                        directives.insert(0, ("encrypt".to_string(), None));
                    }
                }

                entries.push(Entry {
                    directives,
                    key: k.clone(),
                    value: v.clone(),
                    quote_type: qt.clone(),
                });
            }
            // Newlines and whitespace between directives and their kv are fine, skip them.
            // Comments break the directive chain though.
            Line::Comment(_) => {
                pending_directives.clear();
            }
            _ => {}
        }
    }

    entries
}

/// Validate all entries and collect all errors (directives + values).
pub fn validate_entries(entries: &[Entry]) -> Vec<ValidationError> {
    entries.iter().flat_map(|e| e.validate()).collect()
}

/// Validate entries including shell environment variable overrides.
pub fn validate_entries_with_env(entries: &[Entry]) -> Vec<ValidationError> {
    let mut errors = validate_entries(entries);
    for entry in entries {
        if let Ok(env_val) = std::env::var(&entry.key) {
            errors.extend(entry.validate_env_override(&env_val));
        }
    }
    errors
}

/// Compare base entries against target entries and report differences.
pub fn diff_entries(base: &[Entry], target: &[Entry]) -> Vec<DiffItem> {
    let mut diffs = Vec::new();

    let base_keys: Vec<&str> = base.iter().map(|e| e.key.as_str()).collect();
    let target_keys: Vec<&str> = target.iter().map(|e| e.key.as_str()).collect();

    // Missing keys (in base but not in target)
    for entry in base {
        if !target_keys.contains(&entry.key.as_str()) {
            diffs.push(DiffItem::MissingKey { key: entry.key.clone() });
        }
    }

    // Extra keys (in target but not in base)
    for entry in target {
        if !base_keys.contains(&entry.key.as_str()) {
            diffs.push(DiffItem::ExtraKey { key: entry.key.clone() });
        }
    }

    // For keys in both: check directives, values, ordering
    for (base_idx, base_entry) in base.iter().enumerate() {
        if let Some(target_idx) = target.iter().position(|e| e.key == base_entry.key) {
            let target_entry = &target[target_idx];

            // Directive mismatch
            if base_entry.directives != target_entry.directives {
                diffs.push(DiffItem::DirectiveMismatch {
                    key: base_entry.key.clone(),
                    base_directives: base_entry.directives.clone(),
                    target_directives: target_entry.directives.clone(),
                });
            }

            // Value difference (only for non-encrypted entries)
            if !base_entry.has_directive("encrypt") && base_entry.value != target_entry.value {
                diffs.push(DiffItem::ValueDifference {
                    key: base_entry.key.clone(),
                    base_value: base_entry.value.clone(),
                    target_value: target_entry.value.clone(),
                });
            }

            // Ordering difference
            if base_idx != target_idx {
                diffs.push(DiffItem::OrderingDifference {
                    key: base_entry.key.clone(),
                    base_index: base_idx,
                    target_index: target_idx,
                });
            }
        }
    }

    diffs
}

/// Check if a value is in the `ENC[...]` envelope encryption format.
pub fn is_encrypted_value(value: &str) -> bool {
    value.starts_with("ENC[") && value.ends_with(']')
}

pub fn get_value(source: &[Line], key: &str) -> Option<String> {
    source.iter().find_map(|line| {
        if let Line::Kv(k, v, _) = line {
            if k == key { return Some(v.clone()); }
        }
        None
    })
}

/// Parse the .env file source.
pub fn parse_dotenv(source: &str) -> Result<Vec<Line>, Box<pest::error::Error<Rule>>> {
    let mut output: Vec<Line> = Vec::new();

    let pairs = DotenvLineParser::parse(Rule::env, source)?;
    for pair in pairs {
        match pair.as_rule() {
            Rule::NEW_LINE => {
                output.push(Line::Newline);
            }
            Rule::COMMENT => {
                output.push(Line::Comment(pair.as_str().to_string()));
            }
            Rule::directive => {
                for single in pair.into_inner() {
                    if single.as_rule() == Rule::single_directive {
                        let mut inner = single.into_inner();
                        let name = inner.next().unwrap().as_str().to_string();
                        let value = inner.next().map(|v| v.as_str().trim().to_string());
                        output.push(Line::Directive(name, value));
                    }
                }
            }
            Rule::WHITESPACE => {
                output.push(Line::Whitespace(pair.as_str().to_string()));
            }
            Rule::kv => {
                if let Some((key, value, quote_type)) = parse_kv(pair) {
                    output.push(Line::Kv(key, value, quote_type));
                }
            }
            _ => {}
        }
    }

    Ok(output)
}

/// Parse a key-value pair from a pest kv rule.
fn parse_kv(pair: Pair<Rule>) -> Option<(String, String, QuoteType)> {
    if pair.as_rule() != Rule::kv {
        return None;
    }
    let mut inner = pair.into_inner();
    let key = inner.next()?.as_str().to_string();
    let value_pair = inner.next()?;
    let (value, quote_type) = parse_value(value_pair)?;
    Some((key, value, quote_type))
}

/// Parse a value, which might be a quoted string or a naked variable.
///
/// Grammar: value -> string -> (string_dq | string_sq | string_bt | var)
/// For quoted: string_dq -> escaped_dq inner_dq escaped_dq
fn parse_value(pair: Pair<Rule>) -> Option<(String, QuoteType)> {
    if pair.as_rule() != Rule::value {
        return None;
    }

    // value -> string (the $ rule makes string a direct child)
    let string_pair = match pair.clone().into_inner().next() {
        Some(p) => p,
        // Naked value with no inner structure
        None => return Some((pair.as_str().to_string(), QuoteType::None)),
    };

    // string -> string_dq | string_sq | string_bt | var
    let variant = string_pair.into_inner().next()?;

    // For quoted strings (string_dq/sq/bt), children are: escaped_quote, inner_XX, escaped_quote
    // For var, the pair itself is the value
    match variant.as_rule() {
        Rule::string_dq => {
            let inner = variant.into_inner()
                .find(|p| p.as_rule() == Rule::inner_dq)?;
            Some((inner.as_str().to_string(), QuoteType::Double))
        }
        Rule::string_sq => {
            let inner = variant.into_inner()
                .find(|p| p.as_rule() == Rule::inner_sq)?;
            Some((inner.as_str().to_string(), QuoteType::Single))
        }
        Rule::string_bt => {
            let inner = variant.into_inner()
                .find(|p| p.as_rule() == Rule::inner_bt)?;
            Some((inner.as_str().to_string(), QuoteType::Backtick))
        }
        Rule::var => Some((variant.as_str().to_string(), QuoteType::None)),
        _ => Some((variant.as_str().to_string(), QuoteType::None)),
    }
}

pub fn lines_to_json(lines: &[Line]) -> Result<String, serde_json::Error> {
    let output: Vec<HashMap<String, String>> = lines
        .iter()
        .filter_map(|line| {
            if let Line::Kv(k, v, _) = line {
                Some(HashMap::from([(k.clone(), v.clone())]))
            } else {
                None
            }
        })
        .collect();
    serde_json::to_string(&output)
}

pub fn lines_to_csv(lines: &[Line]) -> Result<String, Box<dyn std::error::Error>> {
    let mut output = String::from("name,value\n");
    for line in lines {
        if let Line::Kv(k, v, _) = line {
            output.push_str(&format!("{}\t{}\n", k, v));
        }
    }
    Ok(output)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file() {
        let lines = parse_dotenv("").unwrap();
        assert!(lines.is_empty());
    }

    #[test]
    fn simple_kv() {
        let lines = parse_dotenv("FOO=bar\n").unwrap();
        assert!(matches!(&lines[0], Line::Kv(k, v, QuoteType::None) if k == "FOO" && v == "bar"));
    }

    #[test]
    fn hyphenated_key() {
        let lines = parse_dotenv("cliff-is=\"something\"\n").unwrap();
        assert!(matches!(&lines[0], Line::Kv(k, v, QuoteType::Double) if k == "cliff-is" && v == "something"));
    }

    #[test]
    fn dotted_key() {
        let lines = parse_dotenv("spring.datasource.url=jdbc:foo\n").unwrap();
        assert!(matches!(&lines[0], Line::Kv(k, _, QuoteType::None) if k == "spring.datasource.url"));
    }

    #[test]
    fn quoted_values() {
        let lines = parse_dotenv("A=\"hello\"\nB='world'\n").unwrap();
        assert!(matches!(&lines[0], Line::Kv(_, v, QuoteType::Double) if v == "hello"));
        assert!(matches!(&lines[2], Line::Kv(_, v, QuoteType::Single) if v == "world"));
    }

    #[test]
    fn regular_comment_preserved() {
        let lines = parse_dotenv("# just a comment\nFOO=bar\n").unwrap();
        assert!(matches!(&lines[0], Line::Comment(c) if c.contains("just a comment")));
    }

    #[test]
    fn directive_no_value() {
        let lines = parse_dotenv("# @encrypt\nFOO=bar\n").unwrap();
        assert!(matches!(&lines[0], Line::Directive(name, None) if name == "encrypt"));
        assert!(matches!(&lines[2], Line::Kv(k, _, _) if k == "FOO"));
    }

    #[test]
    fn directive_with_value() {
        let lines = parse_dotenv("# @push=ssm\nFOO=bar\n").unwrap();
        assert!(matches!(&lines[0], Line::Directive(name, Some(val)) if name == "push" && val == "ssm"));
    }

    #[test]
    fn directive_with_complex_value() {
        let lines = parse_dotenv("# @type=enum(development, preview, production)\nFOO=bar\n").unwrap();
        assert!(matches!(&lines[0], Line::Directive(name, Some(val)) if name == "type" && val == "enum(development, preview, production)"));
    }

    #[test]
    fn directive_with_comma_list() {
        let lines = parse_dotenv("# @push=ssm,secretsmanager\nFOO=bar\n").unwrap();
        assert!(matches!(&lines[0], Line::Directive(name, Some(val)) if name == "push" && val == "ssm,secretsmanager"));
    }

    #[test]
    fn directive_with_path() {
        let lines = parse_dotenv("# @ssm-path=/myapp/production\nFOO=bar\n").unwrap();
        assert!(matches!(&lines[0], Line::Directive(name, Some(val)) if name == "ssm-path" && val == "/myapp/production"));
    }

    #[test]
    fn multiple_directives_before_kv() {
        let lines = parse_dotenv("# @encrypt\n# @push=ssm\nFOO=bar\n").unwrap();
        assert!(matches!(&lines[0], Line::Directive(name, None) if name == "encrypt"));
        assert!(matches!(&lines[2], Line::Directive(name, Some(val)) if name == "push" && val == "ssm"));
        assert!(matches!(&lines[4], Line::Kv(k, _, _) if k == "FOO"));
    }

    #[test]
    fn mixed_comments_and_directives() {
        let source = "# Regular comment\n# @encrypt\n# @push=ssm\nDB_URL=\"postgres://localhost\"\n\n# no directives\nDEBUG=true\n";
        let lines = parse_dotenv(source).unwrap();

        let directives: Vec<_> = lines.iter().filter(|l| matches!(l, Line::Directive(_, _))).collect();
        let comments: Vec<_> = lines.iter().filter(|l| matches!(l, Line::Comment(_))).collect();
        let kvs: Vec<_> = lines.iter().filter(|l| matches!(l, Line::Kv(_, _, _))).collect();

        assert_eq!(directives.len(), 2);
        assert_eq!(comments.len(), 2);
        assert_eq!(kvs.len(), 2);
    }

    #[test]
    fn roundtrip_with_directives() {
        let source = "# @encrypt\n# @push=ssm\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let output = lines_to_string(&lines);
        assert_eq!(output, source);
    }

    #[test]
    fn lines_to_entries_groups_directives() {
        let source = "# @encrypt\n# @push=ssm\nDB_URL=\"postgres://localhost\"\n\nDEBUG=true\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);

        assert_eq!(entries.len(), 2);

        // First entry has two directives
        assert_eq!(entries[0].key, "DB_URL");
        assert_eq!(entries[0].directives.len(), 2);
        assert!(entries[0].has_directive("encrypt"));
        assert!(entries[0].has_directive("push"));
        assert_eq!(entries[0].get_directive("push"), Some(&Some("ssm".to_string())));

        // Second entry has no directives
        assert_eq!(entries[1].key, "DEBUG");
        assert_eq!(entries[1].directives.len(), 0);
        assert!(!entries[1].has_directive("encrypt"));
    }

    #[test]
    fn push_target_simple_ssm() {
        let source = "# @push=aws-ssm\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let targets = entries[0].push_targets();
        assert_eq!(targets, vec![PushTarget::AwsSsm(SsmOptions::default())]);
    }

    #[test]
    fn push_target_ssm_legacy_alias() {
        let source = "# @push=ssm\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let targets = entries[0].push_targets();
        assert_eq!(targets, vec![PushTarget::AwsSsm(SsmOptions::default())]);
    }

    #[test]
    fn push_target_ssm_with_path() {
        let source = "# @push=aws-ssm(path=\"/myapp/prod\")\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let targets = entries[0].push_targets();
        assert_eq!(targets, vec![PushTarget::AwsSsm(SsmOptions {
            path: Some("/myapp/prod".to_string()),
            prefix: None,
        })]);
    }

    #[test]
    fn push_target_ssm_with_multiple_params() {
        let source = "# @push=ssm(path=\"/myapp/prod\", prefix=\"MYAPP\")\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let targets = entries[0].push_targets();
        assert_eq!(targets, vec![PushTarget::AwsSsm(SsmOptions {
            path: Some("/myapp/prod".to_string()),
            prefix: Some("MYAPP".to_string()),
        })]);
    }

    #[test]
    fn push_target_multiple_targets() {
        let source = "# @push=ssm(path=\"/myapp/prod\"), secretsmanager\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let targets = entries[0].push_targets();
        assert_eq!(targets, vec![
            PushTarget::AwsSsm(SsmOptions {
                path: Some("/myapp/prod".to_string()),
                prefix: None,
            }),
            PushTarget::AwsSecretsManager(SecretsManagerOptions::default()),
        ]);
    }

    #[test]
    fn push_target_secrets_manager_canonical() {
        let source = "# @push=aws-secrets-manager\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let targets = entries[0].push_targets();
        assert_eq!(targets, vec![PushTarget::AwsSecretsManager(SecretsManagerOptions::default())]);
    }

    #[test]
    fn push_target_secrets_manager_legacy_alias() {
        let source = "# @push=secretsmanager\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let targets = entries[0].push_targets();
        assert_eq!(targets, vec![PushTarget::AwsSecretsManager(SecretsManagerOptions::default())]);
    }

    #[test]
    fn push_target_secrets_manager_hyphenated() {
        let source = "# @push=secrets-manager\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let targets = entries[0].push_targets();
        assert_eq!(targets, vec![PushTarget::AwsSecretsManager(SecretsManagerOptions::default())]);
    }

    #[test]
    fn push_target_secretsmanager_with_path() {
        let source = "# @push=secretsmanager(path=\"/myapp/prod/secrets\")\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let targets = entries[0].push_targets();
        assert_eq!(targets, vec![PushTarget::AwsSecretsManager(SecretsManagerOptions {
            path: Some("/myapp/prod/secrets".to_string()),
        })]);
    }

    #[test]
    fn push_target_unquoted_params_rejected() {
        let source = "# @push=ssm(path=/myapp/prod)\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let targets = entries[0].push_targets();
        // unquoted param value -> no params parsed
        assert_eq!(targets, vec![PushTarget::AwsSsm(SsmOptions::default())]);
    }

    #[test]
    fn var_type_string() {
        let source = "# @type=string\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        assert_eq!(entries[0].var_type(), Some(VarType::String));
    }

    #[test]
    fn var_type_string_quoted() {
        let source = "# @type=\"string\"\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        assert_eq!(entries[0].var_type(), Some(VarType::String));
    }

    #[test]
    fn var_type_number() {
        let source = "# @type=number\nPORT=3000\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        assert_eq!(entries[0].var_type(), Some(VarType::Number));
    }

    #[test]
    fn var_type_boolean() {
        let source = "# @type=boolean\nDEBUG=false\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        assert_eq!(entries[0].var_type(), Some(VarType::Boolean));
    }

    #[test]
    fn var_type_enum_quoted() {
        let source = "# @type=enum(\"development\", \"preview\", \"production\")\nNODE_ENV=\"production\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        assert_eq!(entries[0].var_type(), Some(VarType::Enum(vec![
            "development".to_string(),
            "preview".to_string(),
            "production".to_string(),
        ])));
    }

    #[test]
    fn var_type_enum_unquoted_rejected() {
        let source = "# @type=enum(development, preview, production)\nNODE_ENV=\"production\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        // unquoted enum values -> rejected
        assert_eq!(entries[0].var_type(), None);
    }

    #[test]
    fn no_push_targets_when_no_directive() {
        let source = "FOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        assert_eq!(entries[0].push_targets(), vec![]);
    }

    // --- Validation tests ---

    #[test]
    fn validate_valid_entry() {
        let source = "# @encrypt\n# @type=string\n# @push=aws-ssm(path=\"/myapp\")\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        assert!(errors.is_empty(), "expected no errors, got: {:?}", errors);
    }

    #[test]
    fn validate_unknown_directive() {
        let source = "# @bogus\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("unknown directive"));
    }

    #[test]
    fn validate_encrypt_with_value() {
        let source = "# @encrypt=yes\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("takes no value"));
    }

    #[test]
    fn validate_type_missing_value() {
        let source = "# @type\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("requires a value"));
    }

    #[test]
    fn validate_type_invalid_value() {
        let source = "# @type=potato\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("invalid type"));
    }

    #[test]
    fn validate_type_unquoted_enum() {
        let source = "# @type=enum(dev, prod)\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("must be quoted"));
    }

    #[test]
    fn validate_push_missing_value() {
        let source = "# @push\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("requires a value"));
    }

    #[test]
    fn validate_push_invalid_target() {
        let source = "# @push=gcp-storage\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("no valid push targets"));
    }

    #[test]
    fn validate_collects_all_errors() {
        let source = "# @bogus\n# @type=potato\nFOO=\"bar\"\n\n# @encrypt=yes\n# @push\nBAR=\"baz\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        assert_eq!(errors.len(), 4);
        // FOO has 2 errors: unknown @bogus + invalid @type
        assert_eq!(errors.iter().filter(|e| e.key == "FOO").count(), 2);
        // BAR has 2 errors: @encrypt with value + @push missing value
        assert_eq!(errors.iter().filter(|e| e.key == "BAR").count(), 2);
    }

    #[test]
    fn validate_error_display() {
        let err = ValidationError {
            key: "API_KEY".to_string(),
            message: "invalid type".to_string(),
        };
        assert_eq!(format!("{}", err), "API_KEY: invalid type");
    }

    // --- Value validation tests ---

    #[test]
    fn validate_number_valid() {
        let source = "# @type=number\nPORT=3000\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_number_invalid() {
        let source = "# @type=number\nPORT=hello\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("expected number"));
    }

    #[test]
    fn validate_boolean_valid() {
        let source = "# @type=boolean\nDEBUG=false\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_boolean_invalid() {
        let source = "# @type=boolean\nDEBUG=yes\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("expected boolean"));
    }

    #[test]
    fn validate_enum_valid() {
        let source = "# @type=enum(\"development\", \"production\")\nNODE_ENV=\"production\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_enum_invalid() {
        let source = "# @type=enum(\"development\", \"production\")\nNODE_ENV=\"staging\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("not in enum"));
    }

    #[test]
    fn validate_string_always_valid() {
        let source = "# @type=string\nFOO=literally anything\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        assert!(errors.is_empty());
    }

    // --- File-level default-encrypt tests ---

    #[test]
    fn default_encrypt_applies_to_all_entries() {
        let source = "# @default-encrypt\n\nFOO=\"bar\"\nBAZ=123\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        assert_eq!(entries.len(), 2);
        assert!(entries[0].has_directive("encrypt"));
        assert!(entries[1].has_directive("encrypt"));
    }

    #[test]
    fn default_encrypt_does_not_override_explicit_plaintext() {
        let source = "# @default-encrypt\n\n# @plaintext\nFOO=\"bar\"\nBAZ=123\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        assert_eq!(entries.len(), 2);
        // FOO has explicit @plaintext, should NOT get @encrypt added
        assert!(!entries[0].has_directive("encrypt"));
        assert!(entries[0].has_directive("plaintext"));
        // BAZ has no explicit directive, should get @encrypt from default
        assert!(entries[1].has_directive("encrypt"));
    }

    #[test]
    fn default_plaintext_does_not_add_encrypt() {
        let source = "# @default-plaintext\n\nFOO=\"bar\"\nBAZ=123\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        assert!(!entries[0].has_directive("encrypt"));
        assert!(!entries[1].has_directive("encrypt"));
    }

    #[test]
    fn default_plaintext_does_not_override_explicit_encrypt() {
        let source = "# @default-plaintext\n\n# @encrypt\nSECRET=\"shhh\"\nPORT=3000\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        assert!(entries[0].has_directive("encrypt"));
        assert!(!entries[1].has_directive("encrypt"));
    }

    #[test]
    fn no_default_keeps_behavior_unchanged() {
        let source = "# @encrypt\nFOO=\"bar\"\nBAZ=123\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        assert!(entries[0].has_directive("encrypt"));
        assert!(!entries[1].has_directive("encrypt"));
    }

    // --- Diff tests ---

    #[test]
    fn diff_identical_files() {
        let source = "# @type=string\nFOO=\"bar\"\n\n# @type=number\nPORT=3000\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let diffs = diff_entries(&entries, &entries);
        assert!(diffs.is_empty());
    }

    #[test]
    fn diff_missing_key() {
        let base = "FOO=\"bar\"\nBAZ=\"qux\"\n";
        let target = "FOO=\"bar\"\n";
        let base_entries = lines_to_entries(&parse_dotenv(base).unwrap());
        let target_entries = lines_to_entries(&parse_dotenv(target).unwrap());
        let diffs = diff_entries(&base_entries, &target_entries);
        assert!(diffs.iter().any(|d| matches!(d, DiffItem::MissingKey { key } if key == "BAZ")));
    }

    #[test]
    fn diff_extra_key() {
        let base = "FOO=\"bar\"\n";
        let target = "FOO=\"bar\"\nEXTRA=\"new\"\n";
        let base_entries = lines_to_entries(&parse_dotenv(base).unwrap());
        let target_entries = lines_to_entries(&parse_dotenv(target).unwrap());
        let diffs = diff_entries(&base_entries, &target_entries);
        assert!(diffs.iter().any(|d| matches!(d, DiffItem::ExtraKey { key } if key == "EXTRA")));
    }

    #[test]
    fn diff_directive_mismatch() {
        let base = "# @encrypt\n# @type=string\nFOO=\"bar\"\n";
        let target = "# @type=string\nFOO=\"bar\"\n";
        let base_entries = lines_to_entries(&parse_dotenv(base).unwrap());
        let target_entries = lines_to_entries(&parse_dotenv(target).unwrap());
        let diffs = diff_entries(&base_entries, &target_entries);
        assert!(diffs.iter().any(|d| matches!(d, DiffItem::DirectiveMismatch { key, .. } if key == "FOO")));
    }

    #[test]
    fn diff_value_difference_non_encrypted() {
        let base = "# @type=number\nPORT=3000\n";
        let target = "# @type=number\nPORT=4000\n";
        let base_entries = lines_to_entries(&parse_dotenv(base).unwrap());
        let target_entries = lines_to_entries(&parse_dotenv(target).unwrap());
        let diffs = diff_entries(&base_entries, &target_entries);
        assert!(diffs.iter().any(|d| matches!(d, DiffItem::ValueDifference { key, .. } if key == "PORT")));
    }

    #[test]
    fn diff_no_value_diff_for_encrypted() {
        let base = "# @encrypt\nSECRET=\"aaa\"\n";
        let target = "# @encrypt\nSECRET=\"bbb\"\n";
        let base_entries = lines_to_entries(&parse_dotenv(base).unwrap());
        let target_entries = lines_to_entries(&parse_dotenv(target).unwrap());
        let diffs = diff_entries(&base_entries, &target_entries);
        // Should NOT report value difference for encrypted entries
        assert!(!diffs.iter().any(|d| matches!(d, DiffItem::ValueDifference { .. })));
    }

    #[test]
    fn diff_ordering_difference() {
        let base = "FOO=\"1\"\nBAR=\"2\"\n";
        let target = "BAR=\"2\"\nFOO=\"1\"\n";
        let base_entries = lines_to_entries(&parse_dotenv(base).unwrap());
        let target_entries = lines_to_entries(&parse_dotenv(target).unwrap());
        let diffs = diff_entries(&base_entries, &target_entries);
        assert!(diffs.iter().any(|d| matches!(d, DiffItem::OrderingDifference { key, .. } if key == "FOO")));
        assert!(diffs.iter().any(|d| matches!(d, DiffItem::OrderingDifference { key, .. } if key == "BAR")));
    }

    // --- extract_file_config ---

    #[test]
    fn extract_config_full() {
        let source = "# @provider=aws @key-id=alias/dotsec @region=us-east-1 @default-encrypt\n\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let config = extract_file_config(&lines);
        assert_eq!(config.provider.as_deref(), Some("aws"));
        assert_eq!(config.key_id.as_deref(), Some("alias/dotsec"));
        assert_eq!(config.region.as_deref(), Some("us-east-1"));
        assert_eq!(config.default_encrypt, Some(true));
    }

    #[test]
    fn extract_config_plaintext_default() {
        let source = "# @provider=aws @default-plaintext\n\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let config = extract_file_config(&lines);
        assert_eq!(config.default_encrypt, Some(false));
    }

    #[test]
    fn extract_config_no_config_directives() {
        let source = "FOO=\"bar\"\nBAZ=\"qux\"\n";
        let lines = parse_dotenv(source).unwrap();
        let config = extract_file_config(&lines);
        assert!(config.provider.is_none());
        assert!(config.key_id.is_none());
        assert!(config.region.is_none());
        assert!(config.default_encrypt.is_none());
    }

    #[test]
    fn extract_config_stops_at_first_kv() {
        // Config directives after the first KV should be ignored
        let source = "# @provider=aws\nFOO=\"bar\"\n# @region=eu-west-1\nBAZ=\"qux\"\n";
        let lines = parse_dotenv(source).unwrap();
        let config = extract_file_config(&lines);
        assert_eq!(config.provider.as_deref(), Some("aws"));
        assert!(config.region.is_none()); // after first KV, not picked up
    }

    #[test]
    fn extract_config_does_not_attach_to_entries() {
        let source = "# @provider=aws @key-id=alias/dotsec @region=us-east-1 @default-encrypt\n\n# @plaintext @type=string\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        assert_eq!(entries.len(), 1);
        // Entry should have plaintext+type+encrypt (from default), NOT provider/key-id/region
        let dir_names: Vec<&str> = entries[0].directives.iter().map(|(n, _)| n.as_str()).collect();
        assert!(!dir_names.contains(&"provider"));
        assert!(!dir_names.contains(&"key-id"));
        assert!(!dir_names.contains(&"region"));
        assert!(dir_names.contains(&"plaintext"));
        assert!(dir_names.contains(&"type"));
    }

    #[test]
    fn extract_config_empty_file() {
        let source = "";
        let lines = parse_dotenv(source).unwrap();
        let config = extract_file_config(&lines);
        assert!(config.provider.is_none());
        assert!(config.default_encrypt.is_none());
    }

    #[test]
    fn extract_config_only_directives_no_kvs() {
        let source = "# @provider=aws @key-id=alias/dotsec @region=us-east-1 @default-encrypt\n";
        let lines = parse_dotenv(source).unwrap();
        let config = extract_file_config(&lines);
        assert_eq!(config.provider.as_deref(), Some("aws"));
        assert_eq!(config.default_encrypt, Some(true));
    }
}
