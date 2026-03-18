use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;
use std::collections::HashMap;
pub mod schema;
pub mod types;
#[derive(Parser)]
#[grammar = "dotenv.pest"]
struct DotenvLineParser;
pub use types::{
    DiffItem, Entry, FileConfig, FormatType, Line, PushTarget, QuoteType, Schema, SchemaEntry,
    SecretsManagerOptions, Severity, SsmOptions, ValidationError, VarType,
    SCHEMA_DIRECTIVES, SCHEMA_FILE_LEVEL_DIRECTIVES, ENV_DIRECTIVES,
};

/// Directives whose values need quoting in output: @pattern="...", @deprecated="..."
const QUOTED_VALUE_DIRECTIVES: &[&str] = &["pattern", "deprecated"];

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
                    Some(v) => {
                        if QUOTED_VALUE_DIRECTIVES.contains(&name.as_str()) {
                            output.push_str(&format!("@{}=\"{}\"", name, v));
                        } else {
                            output.push_str(&format!("@{}={}", name, v));
                        }
                    }
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

/// Validate entries against an external schema.
pub fn validate_entries_against_schema(
    entries: &[Entry],
    schema: &Schema,
) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    let entry_keys: Vec<&str> = entries.iter().map(|e| e.key.as_str()).collect();

    // Check for missing keys (in schema but not in .sec)
    for schema_entry in &schema.entries {
        if !entry_keys.contains(&schema_entry.key.as_str()) {
            if schema_entry.has_directive("optional") {
                continue;
            }
            errors.push(ValidationError::error(
                &schema_entry.key,
                "required by schema but missing from .sec file",
            ));
        }
    }

    // Check for extra keys (in .sec but not in schema)
    let schema_keys = schema.keys();
    for entry in entries {
        if !schema_keys.contains(&entry.key.as_str()) {
            errors.push(ValidationError::warning(
                &entry.key,
                "not defined in schema",
            ));
        }
    }

    // Validate each entry against its schema definition
    for entry in entries {
        if let Some(schema_entry) = schema.get(&entry.key) {
            // Warn about inline per-key directives when schema exists
            for (name, _) in &entry.directives {
                if SCHEMA_DIRECTIVES.contains(&name.as_str()) {
                    errors.push(ValidationError::warning(
                        &entry.key,
                        format!("inline @{} directive ignored, using schema", name),
                    ));
                }
            }

            // Validate type from schema
            if let Some(var_type) = schema_entry.var_type() {
                entry.validate_value(&var_type, &entry.value, &mut errors);
            }

            // Validate format from schema
            if let Some(format_type) = schema_entry.format_type() {
                if let Some(msg) = format_type.validate(&entry.value) {
                    errors.push(ValidationError::error(&entry.key, msg));
                }
            }

            // Validate pattern from schema
            if let Some(Some(pattern)) = schema_entry.get_directive("pattern") {
                match regex::Regex::new(pattern) {
                    Ok(re) => {
                        if !re.is_match(&entry.value) {
                            errors.push(ValidationError::error(
                                &entry.key,
                                format!("value \"{}\" does not match pattern \"{}\"", entry.value, pattern),
                            ));
                        }
                    }
                    Err(e) => {
                        errors.push(ValidationError::error(
                            &entry.key,
                            format!("invalid regex pattern \"{}\": {}", pattern, e),
                        ));
                    }
                }
            }

            // Validate min/max from schema (only with @type=number)
            if let Some(var_type) = schema_entry.var_type() {
                if var_type == VarType::Number {
                    if let Ok(val) = entry.value.parse::<f64>() {
                        if let Some(Some(min_str)) = schema_entry.get_directive("min") {
                            if let Ok(min) = min_str.parse::<f64>() {
                                if val < min {
                                    errors.push(ValidationError::error(
                                        &entry.key,
                                        format!("value {} is less than minimum {}", val, min),
                                    ));
                                }
                            }
                        }
                        if let Some(Some(max_str)) = schema_entry.get_directive("max") {
                            if let Ok(max) = max_str.parse::<f64>() {
                                if val > max {
                                    errors.push(ValidationError::error(
                                        &entry.key,
                                        format!("value {} is greater than maximum {}", val, max),
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            // Validate min-length/max-length from schema
            if let Some(Some(min_len_str)) = schema_entry.get_directive("min-length") {
                if let Ok(min_len) = min_len_str.parse::<usize>() {
                    if entry.value.len() < min_len {
                        errors.push(ValidationError::error(
                            &entry.key,
                            format!("value length {} is less than minimum length {}", entry.value.len(), min_len),
                        ));
                    }
                }
            }
            if let Some(Some(max_len_str)) = schema_entry.get_directive("max-length") {
                if let Ok(max_len) = max_len_str.parse::<usize>() {
                    if entry.value.len() > max_len {
                        errors.push(ValidationError::error(
                            &entry.key,
                            format!("value length {} exceeds maximum length {}", entry.value.len(), max_len),
                        ));
                    }
                }
            }

            // Validate not-empty from schema
            if schema_entry.has_directive("not-empty") && entry.value.is_empty() {
                errors.push(ValidationError::error(&entry.key, "value must not be empty"));
            }

            // Warn on deprecated from schema
            if schema_entry.has_directive("deprecated") {
                let msg = match schema_entry.get_directive("deprecated") {
                    Some(Some(message)) => format!("deprecated: {}", message),
                    _ => "deprecated".to_string(),
                };
                errors.push(ValidationError::warning(&entry.key, msg));
            }
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

/// Reorder lines in a .sec file to match the key ordering in a schema.
/// File-level directives and leading comments are preserved at the top.
/// Keys not in the schema are appended at the end.
pub fn format_lines_by_schema(lines: &[Line], schema: &Schema) -> Vec<Line> {
    // 1. Separate file-level header (directives + whitespace before first KV or comment) from entries
    let mut header: Vec<Line> = Vec::new();
    let mut found_first_kv = false;

    for line in lines {
        match line {
            Line::Kv(_, _, _) => { found_first_kv = true; break; }
            Line::Comment(_) => { break; } // comments belong to entries, not header
            _ => { header.push(line.clone()); }
        }
    }

    // 2. Group entries: each KV with its preceding lines (comments, directives, whitespace)
    struct EntryBlock {
        preceding: Vec<Line>, // comments + directives + newlines before the KV
        kv: Line,
        key: String,
    }

    let mut blocks: Vec<EntryBlock> = Vec::new();
    let mut pending: Vec<Line> = Vec::new();
    let header_len = header.len();

    for (i, line) in lines.iter().enumerate() {
        // Skip lines already captured in the header
        if i < header_len {
            continue;
        }

        match line {
            Line::Kv(k, _, _) => {
                blocks.push(EntryBlock {
                    preceding: std::mem::take(&mut pending),
                    kv: line.clone(),
                    key: k.clone(),
                });
            }
            _ => {
                // Comments, directives, newlines, whitespace — all travel with the next KV
                pending.push(line.clone());
            }
        }
    }

    // Orphaned trailing lines (comments/newlines after last KV, no following KV)
    let trailing = std::mem::take(&mut pending);

    // 3. Build output: header + entries in schema order + extras
    let mut output = header;

    // Ensure header ends with a blank line
    if !output.is_empty() {
        let ends_with_double_newline = output.len() >= 2
            && matches!(output[output.len() - 1], Line::Newline)
            && matches!(output[output.len() - 2], Line::Newline);
        if !ends_with_double_newline {
            if !matches!(output.last(), Some(Line::Newline)) {
                output.push(Line::Newline);
            }
            output.push(Line::Newline);
        }
    }

    let schema_keys = schema.keys();
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut first_entry = true;

    // Emit entries in schema order
    for schema_key in &schema_keys {
        if let Some(block) = blocks.iter().find(|b| b.key == *schema_key) {
            if !first_entry && block.preceding.is_empty() {
                output.push(Line::Newline);
            }
            first_entry = false;
            used.insert(block.key.clone());

            output.extend(block.preceding.clone());
            output.push(block.kv.clone());
            output.push(Line::Newline);
        }
    }

    // Emit entries not in schema (extras) at the end, but hold __DOTSEC_KEY__ for last
    let mut dotsec_key_block: Option<&EntryBlock> = None;
    for block in &blocks {
        if !used.contains(&block.key) {
            if block.key == "__DOTSEC_KEY__" || block.key == "__DOTSEC__" {
                dotsec_key_block = Some(block);
                continue;
            }
            if !first_entry && block.preceding.is_empty() {
                output.push(Line::Newline);
            }
            first_entry = false;

            output.extend(block.preceding.clone());
            output.push(block.kv.clone());
            output.push(Line::Newline);
        }
    }

    // Orphaned trailing lines (comments after last KV)
    if !trailing.is_empty() {
        output.extend(trailing);
    }

    // __DOTSEC_KEY__ always goes at the very end
    if let Some(block) = dotsec_key_block {
        if !first_entry {
            output.push(Line::Newline);
        }
        // Emit its preceding lines (includes "do not edit" comment if present)
        output.extend(block.preceding.clone());
        output.push(block.kv.clone());
        output.push(Line::Newline);
    }

    output
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

/// Parse directives from a pest directive pair into Line::Directive items.
/// Shared between parse_dotenv and parse_schema.
fn parse_directive(pair: Pair<Rule>) -> Vec<Line> {
    let mut output = Vec::new();
    for single in pair.into_inner() {
        if single.as_rule() == Rule::single_directive {
            let typed = single.into_inner().next().unwrap();
            match typed.as_rule() {
                Rule::flag_directive => {
                    let name = typed.into_inner().next().unwrap().as_str().to_string();
                    output.push(Line::Directive(name, None));
                }
                Rule::push_directive => {
                    let value = typed.as_str().strip_prefix("@push=").unwrap().to_string();
                    output.push(Line::Directive("push".to_string(), Some(value)));
                }
                Rule::type_directive => {
                    let value = typed.as_str().strip_prefix("@type=").unwrap().to_string();
                    output.push(Line::Directive("type".to_string(), Some(value)));
                }
                Rule::format_directive => {
                    let value = typed.as_str().strip_prefix("@format=").unwrap().to_string();
                    output.push(Line::Directive("format".to_string(), Some(value)));
                }
                Rule::numeric_directive => {
                    let mut inner = typed.into_inner();
                    let name = inner.next().unwrap().as_str().to_string();
                    let value = inner.next().unwrap().as_str().to_string();
                    output.push(Line::Directive(name, Some(value)));
                }
                Rule::pattern_directive => {
                    let value = typed.into_inner()
                        .find(|p| p.as_rule() == Rule::pattern_value)
                        .unwrap().as_str().to_string();
                    output.push(Line::Directive("pattern".to_string(), Some(value)));
                }
                Rule::deprecated_directive => {
                    let message = typed.into_inner()
                        .find(|p| p.as_rule() == Rule::deprecated_message)
                        .map(|p| p.as_str().to_string());
                    output.push(Line::Directive("deprecated".to_string(), message));
                }
                Rule::text_directive => {
                    let mut inner = typed.into_inner();
                    let name = inner.next().unwrap().as_str().to_string();
                    let value = inner.next().unwrap().as_str().trim().to_string();
                    output.push(Line::Directive(name, Some(value)));
                }
                _ => {}
            }
        }
    }
    output
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
                output.extend(parse_directive(pair));
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

/// Parse a schema file source. Schema files have bare keys (no = value) with directives.
pub fn parse_schema(source: &str) -> Result<Schema, Box<pest::error::Error<Rule>>> {
    let mut entries = Vec::new();
    let mut pending_directives: Vec<(String, Option<String>)> = Vec::new();

    let pairs = DotenvLineParser::parse(Rule::schema, source)?;
    for pair in pairs {
        match pair.as_rule() {
            Rule::directive => {
                for line in parse_directive(pair) {
                    if let Line::Directive(name, value) = line {
                        pending_directives.push((name, value));
                    }
                }
            }
            Rule::schema_key => {
                let key = pair.into_inner().next().unwrap().as_str().to_string();
                let directives = std::mem::take(&mut pending_directives);
                entries.push(SchemaEntry { directives, key });
            }
            Rule::COMMENT => {
                pending_directives.clear();
            }
            _ => {}
        }
    }

    Ok(Schema { entries })
}

/// Serialize a schema back to file format.
pub fn schema_to_string(schema: &Schema) -> String {
    let mut output = String::new();
    let mut first = true;

    for entry in &schema.entries {
        if !first && !entry.directives.is_empty() {
            output.push('\n');
        }
        first = false;

        if !entry.directives.is_empty() {
            output.push_str("# ");
            for (i, (name, value)) in entry.directives.iter().enumerate() {
                if i > 0 {
                    output.push(' ');
                }
                match value {
                    Some(v) => {
                        if QUOTED_VALUE_DIRECTIVES.contains(&name.as_str()) {
                            output.push_str(&format!("@{}=\"{}\"", name, v));
                        } else {
                            output.push_str(&format!("@{}={}", name, v));
                        }
                    }
                    None => output.push_str(&format!("@{}", name)),
                }
            }
            output.push('\n');
        }

        output.push_str(&entry.key);
        output.push('\n');
    }

    output
}

/// Convert a schema to a JSON Schema object.
pub fn schema_to_json_schema(schema: &Schema) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();

    for entry in &schema.entries {
        let mut prop = serde_json::Map::new();

        // Type
        match entry.var_type() {
            Some(VarType::String) => { prop.insert("type".into(), "string".into()); }
            Some(VarType::Number) => { prop.insert("type".into(), "number".into()); }
            Some(VarType::Boolean) => { prop.insert("type".into(), "boolean".into()); }
            Some(VarType::Enum(variants)) => {
                prop.insert("type".into(), "string".into());
                prop.insert("enum".into(), variants.into_iter().map(serde_json::Value::String).collect());
            }
            None => { prop.insert("type".into(), "string".into()); }
        }

        // Format
        if let Some(fmt) = entry.format_type() {
            let json_format = match fmt {
                FormatType::Email => "email",
                FormatType::Url => "uri",
                FormatType::Uuid => "uuid",
                FormatType::Ipv4 => "ipv4",
                FormatType::Ipv6 => "ipv6",
                FormatType::Date => "date",
                FormatType::Semver => {
                    // No native JSON Schema format — use pattern
                    prop.entry("pattern").or_insert_with(|| "^\\d+\\.\\d+\\.\\d+".into());
                    ""
                }
            };
            if !json_format.is_empty() {
                prop.insert("format".into(), json_format.into());
            }
        }

        // Pattern
        if let Some(pattern) = entry.pattern() {
            prop.insert("pattern".into(), pattern.into());
        }

        // Numeric constraints
        if let Some(min) = entry.min() {
            prop.insert("minimum".into(), f64_to_json_number(min));
        }
        if let Some(max) = entry.max() {
            prop.insert("maximum".into(), f64_to_json_number(max));
        }

        // Length constraints
        if let Some(min_len) = entry.min_length() {
            prop.insert("minLength".into(), min_len.into());
        }
        if let Some(max_len) = entry.max_length() {
            prop.insert("maxLength".into(), max_len.into());
        }

        // not-empty → minLength: 1
        if entry.has_directive("not-empty") && !prop.contains_key("minLength") {
            prop.insert("minLength".into(), 1.into());
        }

        // Description
        if let Some(desc) = entry.description() {
            prop.insert("description".into(), desc.into());
        }

        // Deprecated
        if let Some(msg) = entry.deprecated_message() {
            prop.insert("deprecated".into(), true.into());
            if let Some(text) = msg {
                prop.entry("description")
                    .and_modify(|v| {
                        if let serde_json::Value::String(existing) = v {
                            *existing = format!("[Deprecated: {}] {}", text, existing);
                        }
                    })
                    .or_insert_with(|| format!("Deprecated: {}", text).into());
            }
        }

        // Required
        if entry.is_required() {
            required.push(serde_json::Value::String(entry.key.clone()));
        }

        properties.insert(entry.key.clone(), serde_json::Value::Object(prop));
    }

    let mut schema_obj = serde_json::Map::new();
    schema_obj.insert("$schema".into(), "http://json-schema.org/draft-07/schema#".into());
    schema_obj.insert("type".into(), "object".into());
    if !required.is_empty() {
        schema_obj.insert("required".into(), serde_json::Value::Array(required));
    }
    schema_obj.insert("properties".into(), serde_json::Value::Object(properties));

    serde_json::Value::Object(schema_obj)
}

/// Generate TypeScript code from a schema (interface + parseEnv function).
pub fn schema_to_typescript(schema: &Schema) -> String {
    let mut out = String::new();
    out.push_str("// Generated by dotsec — do not edit\n\n");

    // --- Interface ---
    out.push_str("export interface Env {\n");
    for entry in &schema.entries {
        let ts_type = match entry.var_type() {
            Some(VarType::String) | None => "string".to_string(),
            Some(VarType::Number) => "number".to_string(),
            Some(VarType::Boolean) => "boolean".to_string(),
            Some(VarType::Enum(variants)) => {
                variants.iter().map(|v| format!("\"{}\"", v)).collect::<Vec<_>>().join(" | ")
            }
        };
        let optional = if entry.is_optional() { "?" } else { "" };
        // JSDoc from @description and @deprecated
        let has_desc = entry.description().is_some();
        let has_deprecated = entry.deprecated_message().is_some();
        if has_desc || has_deprecated {
            out.push_str("  /**\n");
            if let Some(desc) = entry.description() {
                out.push_str(&format!("   * {}\n", desc));
            }
            if let Some(msg) = entry.deprecated_message() {
                match msg {
                    Some(text) => out.push_str(&format!("   * @deprecated {}\n", text)),
                    None => out.push_str("   * @deprecated\n"),
                }
            }
            out.push_str("   */\n");
        }
        out.push_str(&format!("  {}{}: {}\n", entry.key, optional, ts_type));
    }
    out.push_str("}\n\n");

    // --- parseEnv function ---
    out.push_str("export function parseEnv(\n");
    out.push_str("  source: Record<string, string | undefined> = process.env\n");
    out.push_str("): Env {\n");
    out.push_str("  const errors: string[] = []\n\n");

    // Required checks
    let required_entries: Vec<&SchemaEntry> = schema.entries.iter().filter(|e| e.is_required()).collect();
    if !required_entries.is_empty() {
        for entry in &required_entries {
            out.push_str(&format!(
                "  if (source.{} === undefined) errors.push(\"{} is required\")\n",
                entry.key, entry.key
            ));
        }
        out.push('\n');
    }

    // Validation checks
    for entry in &schema.entries {
        let key = &entry.key;
        let mut checks = Vec::new();

        // not-empty
        if entry.has_directive("not-empty") {
            checks.push(format!(
                "  if (source.{k} !== undefined && source.{k}.length === 0)\n    errors.push(\"{k} must not be empty\")",
                k = key
            ));
        }

        // type=number validation
        if entry.var_type() == Some(VarType::Number) {
            checks.push(format!(
                "  if (source.{k} !== undefined && isNaN(Number(source.{k})))\n    errors.push(\"{k} must be a number\")",
                k = key
            ));
            if let Some(min) = entry.min() {
                let min_s = format_f64(min);
                checks.push(format!(
                    "  if (source.{k} !== undefined && Number(source.{k}) < {min})\n    errors.push(\"{k} must be >= {min}\")",
                    k = key, min = min_s
                ));
            }
            if let Some(max) = entry.max() {
                let max_s = format_f64(max);
                checks.push(format!(
                    "  if (source.{k} !== undefined && Number(source.{k}) > {max})\n    errors.push(\"{k} must be <= {max}\")",
                    k = key, max = max_s
                ));
            }
        }

        // type=boolean validation
        if entry.var_type() == Some(VarType::Boolean) {
            checks.push(format!(
                "  if (source.{k} !== undefined && ![\"true\", \"false\", \"1\", \"0\"].includes(source.{k}))\n    errors.push(\"{k} must be a boolean (true/false/1/0)\")",
                k = key
            ));
        }

        // enum validation
        if let Some(VarType::Enum(ref variants)) = entry.var_type() {
            let items = variants.iter().map(|v| format!("\"{}\"", v)).collect::<Vec<_>>().join(", ");
            checks.push(format!(
                "  if (source.{k} !== undefined && ![{items}].includes(source.{k}))\n    errors.push(`{k} must be one of: {display}`)",
                k = key,
                items = items,
                display = variants.join(", ")
            ));
        }

        // format validation
        if let Some(fmt) = entry.format_type() {
            let check = match fmt {
                FormatType::Email => Some(format!(
                    "  if (source.{k} !== undefined && source.{k}.length > 0 && !source.{k}.includes(\"@\"))\n    errors.push(\"{k} must be an email\")",
                    k = key
                )),
                FormatType::Url => Some(format!(
                    "  if (source.{k} !== undefined && source.{k}.length > 0 && !source.{k}.startsWith(\"http://\") && !source.{k}.startsWith(\"https://\"))\n    errors.push(\"{k} must be a url\")",
                    k = key
                )),
                FormatType::Uuid => Some(format!(
                    "  if (source.{k} !== undefined && source.{k}.length > 0 && !/^[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}$/i.test(source.{k}))\n    errors.push(\"{k} must be a uuid\")",
                    k = key
                )),
                FormatType::Ipv4 => Some(format!(
                    "  if (source.{k} !== undefined && source.{k}.length > 0 && !/^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.?){{4}}$/.test(source.{k}))\n    errors.push(\"{k} must be an ipv4 address\")",
                    k = key
                )),
                FormatType::Ipv6 => Some(format!(
                    "  if (source.{k} !== undefined && source.{k}.length > 0 && !source.{k}.includes(\":\"))\n    errors.push(\"{k} must be an ipv6 address\")",
                    k = key
                )),
                FormatType::Date => Some(format!(
                    "  if (source.{k} !== undefined && source.{k}.length > 0 && !/^\\d{{4}}-\\d{{2}}-\\d{{2}}$/.test(source.{k}))\n    errors.push(\"{k} must be a date (YYYY-MM-DD)\")",
                    k = key
                )),
                FormatType::Semver => Some(format!(
                    "  if (source.{k} !== undefined && source.{k}.length > 0 && !/^\\d+\\.\\d+\\.\\d+/.test(source.{k}))\n    errors.push(\"{k} must be a semver (MAJOR.MINOR.PATCH)\")",
                    k = key
                )),
            };
            if let Some(c) = check {
                checks.push(c);
            }
        }

        // pattern validation
        if let Some(pattern) = entry.pattern() {
            let escaped = pattern.replace('\\', "\\\\").replace('`', "\\`");
            checks.push(format!(
                "  if (source.{k} !== undefined && source.{k}.length > 0 && !new RegExp(`{pat}`).test(source.{k}))\n    errors.push(\"{k} must match pattern {pat_display}\")",
                k = key,
                pat = escaped,
                pat_display = pattern.replace('"', "\\\"")
            ));
        }

        // min-length / max-length (for strings)
        if let Some(min_len) = entry.min_length() {
            if !entry.has_directive("not-empty") || min_len > 1 {
                checks.push(format!(
                    "  if (source.{k} !== undefined && source.{k}.length < {n})\n    errors.push(\"{k} must be at least {n} characters\")",
                    k = key, n = min_len
                ));
            }
        }
        if let Some(max_len) = entry.max_length() {
            checks.push(format!(
                "  if (source.{k} !== undefined && source.{k}.length > {n})\n    errors.push(\"{k} must be at most {n} characters\")",
                k = key, n = max_len
            ));
        }

        if !checks.is_empty() {
            for check in checks {
                out.push_str(&check);
                out.push('\n');
            }
            out.push('\n');
        }
    }

    // Error throw
    out.push_str("  if (errors.length > 0)\n");
    out.push_str("    throw new Error(`Environment validation failed:\\n${errors.map(e => `  - ${e}`).join(\"\\n\")}`)\n\n");

    // Return object
    out.push_str("  return {\n");
    for entry in &schema.entries {
        let key = &entry.key;
        let is_optional = entry.is_optional();

        let value_expr = match entry.var_type() {
            Some(VarType::Number) => {
                if is_optional {
                    format!("source.{k} !== undefined ? Number(source.{k}) : undefined", k = key)
                } else {
                    format!("Number(source.{}!)", key)
                }
            }
            Some(VarType::Boolean) => {
                if is_optional {
                    format!("source.{k} !== undefined ? source.{k} === \"true\" || source.{k} === \"1\" : undefined", k = key)
                } else {
                    format!("source.{k}! === \"true\" || source.{k}! === \"1\"", k = key)
                }
            }
            Some(VarType::Enum(_)) => {
                if is_optional {
                    format!("source.{k} !== undefined ? source.{k} as Env[\"{k}\"] : undefined", k = key)
                } else {
                    format!("source.{k}! as Env[\"{k}\"]", k = key)
                }
            }
            Some(VarType::String) | None => {
                if is_optional {
                    format!("source.{}", key)
                } else {
                    format!("source.{}!", key)
                }
            }
        };

        out.push_str(&format!("    {}: {},\n", key, value_expr));
    }
    out.push_str("  }\n");
    out.push_str("}\n");

    out
}

/// Convert f64 to a JSON number, using integer representation when possible.
fn f64_to_json_number(v: f64) -> serde_json::Value {
    if v == v.trunc() && v >= i64::MIN as f64 && v <= i64::MAX as f64 {
        serde_json::Value::Number((v as i64).into())
    } else {
        serde_json::Number::from_f64(v)
            .map_or(serde_json::Value::Null, serde_json::Value::Number)
    }
}

/// Format f64 without trailing zeros for codegen output.
fn format_f64(v: f64) -> String {
    if v == v.trunc() {
        format!("{}", v as i64)
    } else {
        format!("{}", v)
    }
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
    use types::Severity;

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
        let lines = parse_dotenv("# @push=aws-ssm\nFOO=bar\n").unwrap();
        assert!(matches!(&lines[0], Line::Directive(name, Some(val)) if name == "push" && val == "aws-ssm"));
    }

    #[test]
    fn directive_with_complex_value() {
        let lines = parse_dotenv("# @type=enum(\"development\", \"preview\", \"production\")\nFOO=bar\n").unwrap();
        assert!(matches!(&lines[0], Line::Directive(name, Some(val)) if name == "type" && val == "enum(\"development\", \"preview\", \"production\")"));
    }

    #[test]
    fn directive_with_comma_list() {
        let lines = parse_dotenv("# @push=aws-ssm, aws-secrets-manager\nFOO=bar\n").unwrap();
        assert!(matches!(&lines[0], Line::Directive(name, Some(val)) if name == "push" && val == "aws-ssm, aws-secrets-manager"));
    }

    #[test]
    fn directive_unknown_name_rejected() {
        assert!(parse_dotenv("# @ssm-path=/myapp/production\nFOO=bar\n").is_err());
    }

    #[test]
    fn multiple_directives_before_kv() {
        let lines = parse_dotenv("# @encrypt\n# @push=aws-ssm\nFOO=bar\n").unwrap();
        assert!(matches!(&lines[0], Line::Directive(name, None) if name == "encrypt"));
        assert!(matches!(&lines[2], Line::Directive(name, Some(val)) if name == "push" && val == "aws-ssm"));
        assert!(matches!(&lines[4], Line::Kv(k, _, _) if k == "FOO"));
    }

    #[test]
    fn mixed_comments_and_directives() {
        let source = "# Regular comment\n# @encrypt\n# @push=aws-ssm\nDB_URL=\"postgres://localhost\"\n\n# no directives\nDEBUG=true\n";
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
        let source = "# @encrypt\n# @push=aws-ssm\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let output = lines_to_string(&lines);
        assert_eq!(output, source);
    }

    #[test]
    fn lines_to_entries_groups_directives() {
        let source = "# @encrypt\n# @push=aws-ssm\nDB_URL=\"postgres://localhost\"\n\nDEBUG=true\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);

        assert_eq!(entries.len(), 2);

        // First entry has two directives
        assert_eq!(entries[0].key, "DB_URL");
        assert_eq!(entries[0].directives.len(), 2);
        assert!(entries[0].has_directive("encrypt"));
        assert!(entries[0].has_directive("push"));
        assert_eq!(entries[0].get_directive("push"), Some(&Some("aws-ssm".to_string())));

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
    fn push_target_ssm_shorthand_rejected() {
        assert!(parse_dotenv("# @push=ssm\nFOO=\"bar\"\n").is_err());
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
    fn push_target_aws_ssm_with_multiple_params() {
        let source = "# @push=aws-ssm(path=\"/myapp/prod\", prefix=\"MYAPP\")\nFOO=\"bar\"\n";
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
        let source = "# @push=aws-ssm(path=\"/myapp/prod\"), aws-secrets-manager\nFOO=\"bar\"\n";
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
    fn push_target_secretsmanager_shorthand_rejected() {
        assert!(parse_dotenv("# @push=secretsmanager\nFOO=\"bar\"\n").is_err());
    }

    #[test]
    fn push_target_secrets_manager_no_prefix_rejected() {
        assert!(parse_dotenv("# @push=secrets-manager\nFOO=\"bar\"\n").is_err());
    }

    #[test]
    fn push_target_aws_secrets_manager_with_path() {
        let source = "# @push=aws-secrets-manager(path=\"/myapp/prod/secrets\")\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let targets = entries[0].push_targets();
        assert_eq!(targets, vec![PushTarget::AwsSecretsManager(SecretsManagerOptions {
            path: Some("/myapp/prod/secrets".to_string()),
        })]);
    }

    #[test]
    fn push_target_unquoted_params_rejected() {
        assert!(parse_dotenv("# @push=aws-ssm(path=/myapp/prod)\nFOO=\"bar\"\n").is_err());
    }

    #[test]
    fn var_type_string() {
        let source = "# @type=string\nFOO=\"bar\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        assert_eq!(entries[0].var_type(), Some(VarType::String));
    }

    #[test]
    fn var_type_string_quoted_rejected() {
        // Quoting type values is not valid syntax
        assert!(parse_dotenv("# @type=\"string\"\nFOO=\"bar\"\n").is_err());
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
        // Unquoted enum values are rejected at parse time
        assert!(parse_dotenv("# @type=enum(development, preview, production)\nNODE_ENV=\"production\"\n").is_err());
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

    // --- Parse-time rejection tests ---
    // These are now caught by the grammar, not by validation.

    #[test]
    fn parse_rejects_unknown_directive() {
        assert!(parse_dotenv("# @bogus\nFOO=\"bar\"\n").is_err());
    }

    #[test]
    fn parse_rejects_encrypt_with_value() {
        assert!(parse_dotenv("# @encrypt=yes\nFOO=\"bar\"\n").is_err());
    }

    #[test]
    fn parse_rejects_type_missing_value() {
        assert!(parse_dotenv("# @type\nFOO=\"bar\"\n").is_err());
    }

    #[test]
    fn parse_rejects_type_invalid_value() {
        assert!(parse_dotenv("# @type=potato\nFOO=\"bar\"\n").is_err());
    }

    #[test]
    fn parse_rejects_type_unquoted_enum() {
        assert!(parse_dotenv("# @type=enum(dev, prod)\nFOO=\"bar\"\n").is_err());
    }

    #[test]
    fn parse_rejects_push_missing_value() {
        assert!(parse_dotenv("# @push\nFOO=\"bar\"\n").is_err());
    }

    #[test]
    fn parse_rejects_push_invalid_target() {
        assert!(parse_dotenv("# @push=gcp-storage\nFOO=\"bar\"\n").is_err());
    }

    #[test]
    fn parse_rejects_mixed_invalid_directives() {
        // Each of these should individually fail to parse
        assert!(parse_dotenv("# @bogus\nFOO=\"bar\"\n").is_err());
        assert!(parse_dotenv("# @encrypt=yes\nFOO=\"bar\"\n").is_err());
        assert!(parse_dotenv("# @push\nBAR=\"baz\"\n").is_err());
    }

    #[test]
    fn validate_error_display() {
        let err = ValidationError::error("API_KEY", "invalid type");
        assert_eq!(format!("{}", err), "API_KEY: invalid type");
    }

    #[test]
    fn validate_warning_display() {
        let err = ValidationError::warning("OLD_KEY", "deprecated");
        assert_eq!(format!("{}", err), "OLD_KEY: [warning] deprecated");
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

    // --- New directive parse tests ---

    #[test]
    fn parse_format_directive() {
        let source = "# @format=email\nFOO=\"test@example.com\"\n";
        let lines = parse_dotenv(source).unwrap();
        assert!(matches!(&lines[0], Line::Directive(name, Some(val)) if name == "format" && val == "email"));
    }

    #[test]
    fn parse_format_invalid_rejected() {
        assert!(parse_dotenv("# @format=potato\nFOO=\"bar\"\n").is_err());
    }

    #[test]
    fn parse_numeric_directives() {
        let source = "# @type=number @min=0 @max=65535\nPORT=3000\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        assert!(entries[0].has_directive("min"));
        assert!(entries[0].has_directive("max"));
        assert_eq!(entries[0].get_directive("min"), Some(&Some("0".to_string())));
        assert_eq!(entries[0].get_directive("max"), Some(&Some("65535".to_string())));
    }

    #[test]
    fn parse_min_length_max_length() {
        let source = "# @min-length=1 @max-length=255\nNAME=\"foo\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        assert!(entries[0].has_directive("min-length"));
        assert!(entries[0].has_directive("max-length"));
    }

    #[test]
    fn parse_pattern_directive() {
        let source = "# @pattern=\"^https?://\"\nURL=\"https://example.com\"\n";
        let lines = parse_dotenv(source).unwrap();
        assert!(matches!(&lines[0], Line::Directive(name, Some(val)) if name == "pattern" && val == "^https?://"));
    }

    #[test]
    fn parse_deprecated_no_message() {
        let source = "# @deprecated\nOLD_KEY=\"value\"\n";
        let lines = parse_dotenv(source).unwrap();
        assert!(matches!(&lines[0], Line::Directive(name, None) if name == "deprecated"));
    }

    #[test]
    fn parse_deprecated_with_message() {
        let source = "# @deprecated=\"Use NEW_KEY instead\"\nOLD_KEY=\"value\"\n";
        let lines = parse_dotenv(source).unwrap();
        assert!(matches!(&lines[0], Line::Directive(name, Some(val)) if name == "deprecated" && val == "Use NEW_KEY instead"));
    }

    #[test]
    fn parse_optional_directive() {
        let source = "# @optional\nSENTRY_DSN=\"https://sentry.io\"\n";
        let lines = parse_dotenv(source).unwrap();
        assert!(matches!(&lines[0], Line::Directive(name, None) if name == "optional"));
    }

    #[test]
    fn parse_not_empty_directive() {
        let source = "# @not-empty\nNAME=\"foo\"\n";
        let lines = parse_dotenv(source).unwrap();
        assert!(matches!(&lines[0], Line::Directive(name, None) if name == "not-empty"));
    }

    // --- New directive validation tests ---

    #[test]
    fn validate_format_email_valid() {
        let source = "# @format=email\nADMIN=\"admin@example.com\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors: Vec<_> = validate_entries(&entries).into_iter().filter(|e| e.severity == Severity::Error).collect();
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_format_email_invalid() {
        let source = "# @format=email\nADMIN=\"not-an-email\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors: Vec<_> = validate_entries(&entries).into_iter().filter(|e| e.severity == Severity::Error).collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("email"));
    }

    #[test]
    fn validate_format_url_valid() {
        let source = "# @format=url\nAPI=\"https://api.example.com\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors: Vec<_> = validate_entries(&entries).into_iter().filter(|e| e.severity == Severity::Error).collect();
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_format_url_invalid() {
        let source = "# @format=url\nAPI=\"ftp://nope\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors: Vec<_> = validate_entries(&entries).into_iter().filter(|e| e.severity == Severity::Error).collect();
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn validate_format_uuid_valid() {
        let source = "# @format=uuid\nID=\"550e8400-e29b-41d4-a716-446655440000\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors: Vec<_> = validate_entries(&entries).into_iter().filter(|e| e.severity == Severity::Error).collect();
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_format_uuid_invalid() {
        let source = "# @format=uuid\nID=\"not-a-uuid\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors: Vec<_> = validate_entries(&entries).into_iter().filter(|e| e.severity == Severity::Error).collect();
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn validate_pattern_match() {
        let source = "# @pattern=\"^https?://\"\nURL=\"https://example.com\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors: Vec<_> = validate_entries(&entries).into_iter().filter(|e| e.severity == Severity::Error).collect();
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_pattern_no_match() {
        let source = "# @pattern=\"^https?://\"\nURL=\"ftp://example.com\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors: Vec<_> = validate_entries(&entries).into_iter().filter(|e| e.severity == Severity::Error).collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("does not match pattern"));
    }

    #[test]
    fn validate_min_max_valid() {
        let source = "# @type=number @min=0 @max=65535\nPORT=3000\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors: Vec<_> = validate_entries(&entries).into_iter().filter(|e| e.severity == Severity::Error).collect();
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_min_violation() {
        let source = "# @type=number @min=1\nPORT=-5\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors: Vec<_> = validate_entries(&entries).into_iter().filter(|e| e.severity == Severity::Error).collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("less than minimum"));
    }

    #[test]
    fn validate_max_violation() {
        let source = "# @type=number @max=100\nPORT=99999\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors: Vec<_> = validate_entries(&entries).into_iter().filter(|e| e.severity == Severity::Error).collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("greater than maximum"));
    }

    #[test]
    fn validate_min_length_violation() {
        let source = "# @min-length=5\nNAME=\"ab\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors: Vec<_> = validate_entries(&entries).into_iter().filter(|e| e.severity == Severity::Error).collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("less than minimum length"));
    }

    #[test]
    fn validate_max_length_violation() {
        let source = "# @max-length=3\nNAME=\"toolong\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors: Vec<_> = validate_entries(&entries).into_iter().filter(|e| e.severity == Severity::Error).collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("exceeds maximum length"));
    }

    #[test]
    fn validate_not_empty_valid() {
        let source = "# @not-empty\nNAME=\"foo\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors: Vec<_> = validate_entries(&entries).into_iter().filter(|e| e.severity == Severity::Error).collect();
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_not_empty_violation() {
        let source = "# @not-empty\nNAME=\"\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors: Vec<_> = validate_entries(&entries).into_iter().filter(|e| e.severity == Severity::Error).collect();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("must not be empty"));
    }

    #[test]
    fn validate_deprecated_warning() {
        let source = "# @deprecated=\"Use NEW_KEY instead\"\nOLD_KEY=\"value\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        let warnings: Vec<_> = errors.iter().filter(|e| e.severity == Severity::Warning).collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("deprecated"));
        assert!(warnings[0].message.contains("Use NEW_KEY instead"));
    }

    #[test]
    fn validate_deprecated_no_message_warning() {
        let source = "# @deprecated\nOLD_KEY=\"value\"\n";
        let lines = parse_dotenv(source).unwrap();
        let entries = lines_to_entries(&lines);
        let errors = validate_entries(&entries);
        let warnings: Vec<_> = errors.iter().filter(|e| e.severity == Severity::Warning).collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message == "deprecated");
    }

    // --- Roundtrip tests for new directives ---

    #[test]
    fn roundtrip_pattern() {
        let source = "# @pattern=\"^https?://\"\nURL=\"https://example.com\"\n";
        let lines = parse_dotenv(source).unwrap();
        let output = lines_to_string(&lines);
        assert_eq!(output, source);
    }

    #[test]
    fn roundtrip_deprecated_with_message() {
        let source = "# @deprecated=\"Use NEW_KEY\"\nOLD=\"val\"\n";
        let lines = parse_dotenv(source).unwrap();
        let output = lines_to_string(&lines);
        assert_eq!(output, source);
    }

    #[test]
    fn roundtrip_deprecated_no_message() {
        let source = "# @deprecated\nOLD=\"val\"\n";
        let lines = parse_dotenv(source).unwrap();
        let output = lines_to_string(&lines);
        assert_eq!(output, source);
    }

    #[test]
    fn roundtrip_format() {
        let source = "# @format=email\nADMIN=\"test@example.com\"\n";
        let lines = parse_dotenv(source).unwrap();
        let output = lines_to_string(&lines);
        assert_eq!(output, source);
    }

    #[test]
    fn roundtrip_numeric_directives() {
        let source = "# @type=number @min=0 @max=65535\nPORT=3000\n";
        let lines = parse_dotenv(source).unwrap();
        let output = lines_to_string(&lines);
        assert_eq!(output, source);
    }

    #[test]
    fn roundtrip_optional_not_empty() {
        let source = "# @optional @not-empty\nSENTRY=\"https://sentry.io\"\n";
        let lines = parse_dotenv(source).unwrap();
        let output = lines_to_string(&lines);
        assert_eq!(output, source);
    }

    // --- Schema parse tests ---

    #[test]
    fn parse_schema_simple() {
        let source = "# @type=string\nDATABASE_URL\n\n# @type=number\nPORT\n";
        let schema = parse_schema(source).unwrap();
        assert_eq!(schema.entries.len(), 2);
        assert_eq!(schema.entries[0].key, "DATABASE_URL");
        assert_eq!(schema.entries[1].key, "PORT");
        assert!(schema.entries[0].has_directive("type"));
    }

    #[test]
    fn parse_schema_with_all_directives() {
        let source = "# @default-encrypt\n\n# @type=string @push=aws-ssm @not-empty\nDATABASE_URL\n\n# @type=number @min=0 @max=65535\nPORT\n\n# @type=enum(\"development\", \"production\")\nNODE_ENV\n\n# @optional @format=url\nSENTRY_DSN\n";
        let schema = parse_schema(source).unwrap();
        assert_eq!(schema.entries.len(), 4);
        assert_eq!(schema.get("PORT").unwrap().key, "PORT");
        assert!(schema.get("SENTRY_DSN").unwrap().has_directive("optional"));
    }

    #[test]
    fn schema_roundtrip() {
        let source = "# @type=string @push=aws-ssm\nDATABASE_URL\n\n# @type=number @min=0 @max=65535\nPORT\n\n# @type=enum(\"development\", \"production\")\nNODE_ENV\n";
        let schema = parse_schema(source).unwrap();
        let output = schema_to_string(&schema);
        let reparsed = parse_schema(&output).unwrap();
        assert_eq!(reparsed.entries.len(), schema.entries.len());
        for (a, b) in schema.entries.iter().zip(reparsed.entries.iter()) {
            assert_eq!(a.key, b.key);
            assert_eq!(a.directives, b.directives);
        }
    }

    #[test]
    fn schema_get_nonexistent() {
        let source = "# @type=string\nFOO\n";
        let schema = parse_schema(source).unwrap();
        assert!(schema.get("BAR").is_none());
    }

    // --- Schema validation tests ---

    #[test]
    fn schema_validation_missing_required_key() {
        let schema_src = "# @type=string\nDATABASE_URL\n\n# @type=number\nPORT\n";
        let sec_src = "PORT=3000\n";
        let schema = parse_schema(schema_src).unwrap();
        let entries = lines_to_entries(&parse_dotenv(sec_src).unwrap());
        let errors = validate_entries_against_schema(&entries, &schema);
        assert!(errors.iter().any(|e| e.key == "DATABASE_URL" && e.severity == Severity::Error));
    }

    #[test]
    fn schema_validation_optional_key_not_error() {
        let schema_src = "# @optional @type=string\nSENTRY_DSN\n\n# @type=number\nPORT\n";
        let sec_src = "PORT=3000\n";
        let schema = parse_schema(schema_src).unwrap();
        let entries = lines_to_entries(&parse_dotenv(sec_src).unwrap());
        let errors = validate_entries_against_schema(&entries, &schema);
        assert!(!errors.iter().any(|e| e.key == "SENTRY_DSN" && e.severity == Severity::Error));
    }

    #[test]
    fn schema_validation_extra_key_warning() {
        let schema_src = "# @type=number\nPORT\n";
        let sec_src = "PORT=3000\nEXTRA=foo\n";
        let schema = parse_schema(schema_src).unwrap();
        let entries = lines_to_entries(&parse_dotenv(sec_src).unwrap());
        let errors = validate_entries_against_schema(&entries, &schema);
        assert!(errors.iter().any(|e| e.key == "EXTRA" && e.severity == Severity::Warning));
    }

    #[test]
    fn schema_validation_type_mismatch() {
        let schema_src = "# @type=number\nPORT\n";
        let sec_src = "PORT=hello\n";
        let schema = parse_schema(schema_src).unwrap();
        let entries = lines_to_entries(&parse_dotenv(sec_src).unwrap());
        let errors = validate_entries_against_schema(&entries, &schema);
        assert!(errors.iter().any(|e| e.key == "PORT" && e.message.contains("expected number")));
    }

    #[test]
    fn schema_validation_inline_directive_warning() {
        let schema_src = "# @type=string\nFOO\n";
        let sec_src = "# @type=number\nFOO=\"bar\"\n";
        let schema = parse_schema(schema_src).unwrap();
        let entries = lines_to_entries(&parse_dotenv(sec_src).unwrap());
        let errors = validate_entries_against_schema(&entries, &schema);
        assert!(errors.iter().any(|e| e.key == "FOO" && e.message.contains("inline @type directive ignored")));
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

    // --- JSON Schema export tests ---

    #[test]
    fn json_schema_basic_shape() {
        let schema = parse_schema("# @type=string\nFOO\n\n# @type=number\nBAR\n").unwrap();
        let js = schema_to_json_schema(&schema);
        assert_eq!(js["$schema"], "http://json-schema.org/draft-07/schema#");
        assert_eq!(js["type"], "object");
        assert!(js["required"].as_array().unwrap().contains(&serde_json::Value::String("FOO".into())));
        assert_eq!(js["properties"]["FOO"]["type"], "string");
        assert_eq!(js["properties"]["BAR"]["type"], "number");
    }

    #[test]
    fn json_schema_optional_not_required() {
        let schema = parse_schema("# @optional @type=string\nFOO\n\n# @type=string\nBAR\n").unwrap();
        let js = schema_to_json_schema(&schema);
        let required = js["required"].as_array().unwrap();
        assert!(!required.contains(&serde_json::Value::String("FOO".into())));
        assert!(required.contains(&serde_json::Value::String("BAR".into())));
    }

    #[test]
    fn json_schema_enum() {
        let schema = parse_schema("# @type=enum(\"a\", \"b\", \"c\")\nFOO\n").unwrap();
        let js = schema_to_json_schema(&schema);
        assert_eq!(js["properties"]["FOO"]["type"], "string");
        let variants = js["properties"]["FOO"]["enum"].as_array().unwrap();
        assert_eq!(variants.len(), 3);
    }

    #[test]
    fn json_schema_boolean() {
        let schema = parse_schema("# @type=boolean\nDEBUG\n").unwrap();
        let js = schema_to_json_schema(&schema);
        assert_eq!(js["properties"]["DEBUG"]["type"], "boolean");
    }

    #[test]
    fn json_schema_format_url() {
        let schema = parse_schema("# @format=url\nAPI\n").unwrap();
        let js = schema_to_json_schema(&schema);
        assert_eq!(js["properties"]["API"]["format"], "uri");
    }

    #[test]
    fn json_schema_format_email() {
        let schema = parse_schema("# @format=email\nADMIN\n").unwrap();
        let js = schema_to_json_schema(&schema);
        assert_eq!(js["properties"]["ADMIN"]["format"], "email");
    }

    #[test]
    fn json_schema_constraints() {
        let schema = parse_schema("# @type=number @min=0 @max=65535\nPORT\n").unwrap();
        let js = schema_to_json_schema(&schema);
        assert_eq!(js["properties"]["PORT"]["minimum"], 0.0);
        assert_eq!(js["properties"]["PORT"]["maximum"], 65535.0);
    }

    #[test]
    fn json_schema_length_constraints() {
        let schema = parse_schema("# @min-length=1 @max-length=255\nNAME\n").unwrap();
        let js = schema_to_json_schema(&schema);
        assert_eq!(js["properties"]["NAME"]["minLength"], 1);
        assert_eq!(js["properties"]["NAME"]["maxLength"], 255);
    }

    #[test]
    fn json_schema_not_empty() {
        let schema = parse_schema("# @not-empty\nFOO\n").unwrap();
        let js = schema_to_json_schema(&schema);
        assert_eq!(js["properties"]["FOO"]["minLength"], 1);
    }

    #[test]
    fn json_schema_pattern() {
        let schema = parse_schema("# @pattern=\"^https?://\"\nURL\n").unwrap();
        let js = schema_to_json_schema(&schema);
        assert_eq!(js["properties"]["URL"]["pattern"], "^https?://");
    }

    #[test]
    fn json_schema_deprecated() {
        let schema = parse_schema("# @deprecated=\"Use NEW_KEY\"\nOLD\n").unwrap();
        let js = schema_to_json_schema(&schema);
        assert_eq!(js["properties"]["OLD"]["deprecated"], true);
        assert!(js["properties"]["OLD"]["description"].as_str().unwrap().contains("Deprecated"));
    }

    #[test]
    fn json_schema_description() {
        let schema = parse_schema("# @description=Database connection string\nDB_URL\n").unwrap();
        let js = schema_to_json_schema(&schema);
        assert_eq!(js["properties"]["DB_URL"]["description"], "Database connection string");
    }

    // --- TypeScript codegen tests ---

    #[test]
    fn typescript_interface_types() {
        let schema = parse_schema("# @type=string\nFOO\n\n# @type=number\nBAR\n\n# @type=boolean\nBAZ\n").unwrap();
        let ts = schema_to_typescript(&schema);
        assert!(ts.contains("FOO: string"));
        assert!(ts.contains("BAR: number"));
        assert!(ts.contains("BAZ: boolean"));
    }

    #[test]
    fn typescript_enum_type() {
        let schema = parse_schema("# @type=enum(\"dev\", \"prod\")\nENV\n").unwrap();
        let ts = schema_to_typescript(&schema);
        assert!(ts.contains("ENV: \"dev\" | \"prod\""));
    }

    #[test]
    fn typescript_optional_field() {
        let schema = parse_schema("# @optional @type=string\nFOO\n").unwrap();
        let ts = schema_to_typescript(&schema);
        assert!(ts.contains("FOO?: string"));
    }

    #[test]
    fn typescript_required_check() {
        let schema = parse_schema("# @type=string\nFOO\n").unwrap();
        let ts = schema_to_typescript(&schema);
        assert!(ts.contains("FOO is required"));
    }

    #[test]
    fn typescript_optional_no_required_check() {
        let schema = parse_schema("# @optional\nFOO\n").unwrap();
        let ts = schema_to_typescript(&schema);
        assert!(!ts.contains("FOO is required"));
    }

    #[test]
    fn typescript_number_cast() {
        let schema = parse_schema("# @type=number\nPORT\n").unwrap();
        let ts = schema_to_typescript(&schema);
        assert!(ts.contains("Number(source.PORT!)"));
    }

    #[test]
    fn typescript_boolean_cast() {
        let schema = parse_schema("# @type=boolean\nDEBUG\n").unwrap();
        let ts = schema_to_typescript(&schema);
        assert!(ts.contains("=== \"true\" || source.DEBUG! === \"1\""));
    }

    #[test]
    fn typescript_enum_cast() {
        let schema = parse_schema("# @type=enum(\"dev\", \"prod\")\nENV\n").unwrap();
        let ts = schema_to_typescript(&schema);
        assert!(ts.contains("as Env[\"ENV\"]"));
    }

    #[test]
    fn typescript_min_max_validation() {
        let schema = parse_schema("# @type=number @min=0 @max=65535\nPORT\n").unwrap();
        let ts = schema_to_typescript(&schema);
        assert!(ts.contains("must be a number"));
        assert!(ts.contains("must be >= 0"));
        assert!(ts.contains("must be <= 65535"));
    }

    #[test]
    fn typescript_not_empty_validation() {
        let schema = parse_schema("# @not-empty\nFOO\n").unwrap();
        let ts = schema_to_typescript(&schema);
        assert!(ts.contains("must not be empty"));
    }

    #[test]
    fn typescript_enum_validation() {
        let schema = parse_schema("# @type=enum(\"a\", \"b\")\nFOO\n").unwrap();
        let ts = schema_to_typescript(&schema);
        assert!(ts.contains("[\"a\", \"b\"].includes"));
    }

    #[test]
    fn typescript_format_url_validation() {
        let schema = parse_schema("# @format=url\nAPI\n").unwrap();
        let ts = schema_to_typescript(&schema);
        assert!(ts.contains("must be a url"));
    }

    #[test]
    fn typescript_pattern_validation() {
        let schema = parse_schema("# @pattern=\"^https?://\"\nURL\n").unwrap();
        let ts = schema_to_typescript(&schema);
        assert!(ts.contains("new RegExp"));
        assert!(ts.contains("must match pattern"));
    }

    #[test]
    fn typescript_has_header() {
        let schema = parse_schema("# @type=string\nFOO\n").unwrap();
        let ts = schema_to_typescript(&schema);
        assert!(ts.starts_with("// Generated by dotsec"));
    }

    #[test]
    fn typescript_has_parseenv_function() {
        let schema = parse_schema("# @type=string\nFOO\n").unwrap();
        let ts = schema_to_typescript(&schema);
        assert!(ts.contains("export function parseEnv("));
        assert!(ts.contains("process.env"));
        assert!(ts.contains("): Env {"));
    }

    #[test]
    fn typescript_error_throw() {
        let schema = parse_schema("# @type=string\nFOO\n").unwrap();
        let ts = schema_to_typescript(&schema);
        assert!(ts.contains("throw new Error(`Environment validation failed"));
    }

    // --- format_lines_by_schema tests ---

    #[test]
    fn format_preserves_comments_before_entries() {
        let schema = parse_schema("FOO\nBAR\n").unwrap();
        let lines = parse_dotenv("# a comment\nFOO=\"1\"\n\n# another comment\nBAR=\"2\"\n").unwrap();
        let formatted = format_lines_by_schema(&lines, &schema);
        let output = lines_to_string(&formatted);
        assert!(output.contains("# a comment"), "comment before FOO lost");
        assert!(output.contains("# another comment"), "comment before BAR lost");
    }

    #[test]
    fn format_comments_travel_with_entry() {
        // Schema order: BAR, FOO — reverse of file order
        let schema = parse_schema("BAR\nFOO\n").unwrap();
        let lines = parse_dotenv("# foo comment\nFOO=\"1\"\n\n# bar comment\nBAR=\"2\"\n").unwrap();
        let formatted = format_lines_by_schema(&lines, &schema);
        let output = lines_to_string(&formatted);
        // BAR should come first, with its comment
        let bar_pos = output.find("BAR=").unwrap();
        let foo_pos = output.find("FOO=").unwrap();
        assert!(bar_pos < foo_pos, "BAR should come before FOO");
        let bar_comment_pos = output.find("# bar comment").unwrap();
        assert!(bar_comment_pos < bar_pos, "bar comment should precede BAR");
        let foo_comment_pos = output.find("# foo comment").unwrap();
        assert!(foo_comment_pos < foo_pos, "foo comment should precede FOO");
        assert!(foo_comment_pos > bar_pos, "foo comment should come after BAR");
    }

    #[test]
    fn format_preserves_trailing_comment() {
        let schema = parse_schema("FOO\n").unwrap();
        let lines = parse_dotenv("FOO=\"1\"\n\n# trailing comment\n").unwrap();
        let formatted = format_lines_by_schema(&lines, &schema);
        let output = lines_to_string(&formatted);
        assert!(output.contains("# trailing comment"), "trailing comment lost");
    }

    #[test]
    fn format_preserves_blank_lines_between_comment_and_kv() {
        let schema = parse_schema("FOO\n").unwrap();
        let lines = parse_dotenv("# section header\n\nFOO=\"1\"\n").unwrap();
        let formatted = format_lines_by_schema(&lines, &schema);
        let output = lines_to_string(&formatted);
        assert!(output.contains("# section header\n\nFOO="), "blank line between comment and KV lost");
    }

    #[test]
    fn format_dotsec_key_stays_last() {
        let schema = parse_schema("FOO\nBAR\n").unwrap();
        let lines = parse_dotenv("FOO=\"1\"\nBAR=\"2\"\n\n# do not edit the line below, it is managed by dotsec\n__DOTSEC_KEY__=\"wrapped\"\n").unwrap();
        let formatted = format_lines_by_schema(&lines, &schema);
        let output = lines_to_string(&formatted);
        let key_pos = output.find("__DOTSEC_KEY__=").unwrap();
        let bar_pos = output.find("BAR=").unwrap();
        assert!(key_pos > bar_pos, "__DOTSEC_KEY__ should be after BAR");
        assert!(output.contains("do not edit"), "managed comment should be preserved");
    }
}
