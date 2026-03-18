use napi_derive::napi;

#[napi(object)]
pub struct ParsedEntry {
    pub key: String,
    pub value: String,
    pub quote_type: String,
    pub directives: Vec<DirectiveItem>,
}

#[napi(object)]
pub struct DirectiveItem {
    pub name: String,
    pub value: Option<String>,
}

#[napi(object)]
pub struct ParsedValidationError {
    pub key: String,
    pub message: String,
    pub severity: String,
}

#[napi(object)]
pub struct ParsedSchemaEntry {
    pub key: String,
    pub directives: Vec<DirectiveItem>,
}

/// Parse a .env file string and return entries with their directives.
#[napi]
pub fn parse(source: String) -> napi::Result<Vec<ParsedEntry>> {
    let lines = dotsec_core::dotenv::parse_dotenv(&source)
        .map_err(|e| napi::Error::from_reason(format!("Parse error: {e}")))?;
    let entries = dotsec_core::dotenv::lines_to_entries(&lines);

    Ok(entries
        .into_iter()
        .map(|e| ParsedEntry {
            key: e.key,
            value: e.value,
            quote_type: format!("{:?}", e.quote_type),
            directives: e
                .directives
                .into_iter()
                .map(|(name, value)| DirectiveItem { name, value })
                .collect(),
        })
        .collect())
}

/// Validate entries from a .env file string. Returns a list of validation errors.
#[napi]
pub fn validate(source: String) -> napi::Result<Vec<ParsedValidationError>> {
    let lines = dotsec_core::dotenv::parse_dotenv(&source)
        .map_err(|e| napi::Error::from_reason(format!("Parse error: {e}")))?;
    let entries = dotsec_core::dotenv::lines_to_entries(&lines);
    let errors = dotsec_core::dotenv::validate_entries(&entries);

    Ok(errors
        .into_iter()
        .map(|e| ParsedValidationError {
            key: e.key,
            message: e.message,
            severity: format!("{:?}", e.severity),
        })
        .collect())
}

/// Validate a .env file against a schema string. Returns validation errors.
#[napi]
pub fn validate_against_schema(source: String, schema_source: String) -> napi::Result<Vec<ParsedValidationError>> {
    let lines = dotsec_core::dotenv::parse_dotenv(&source)
        .map_err(|e| napi::Error::from_reason(format!("Parse error: {e}")))?;
    let entries = dotsec_core::dotenv::lines_to_entries(&lines);
    let schema = dotsec_core::dotenv::parse_schema(&schema_source)
        .map_err(|e| napi::Error::from_reason(format!("Schema parse error: {e}")))?;
    let errors = dotsec_core::dotenv::validate_entries_against_schema(&entries, &schema);

    Ok(errors
        .into_iter()
        .map(|e| ParsedValidationError {
            key: e.key,
            message: e.message,
            severity: format!("{:?}", e.severity),
        })
        .collect())
}

/// Convert a .env file string to JSON.
#[napi]
pub fn to_json(source: String) -> napi::Result<String> {
    let lines = dotsec_core::dotenv::parse_dotenv(&source)
        .map_err(|e| napi::Error::from_reason(format!("Parse error: {e}")))?;
    dotsec_core::dotenv::lines_to_json(&lines).map_err(|e| napi::Error::from_reason(format!("JSON error: {e}")))
}

/// Roundtrip: parse a .env file string and serialize it back.
#[napi]
pub fn format(source: String) -> napi::Result<String> {
    let lines = dotsec_core::dotenv::parse_dotenv(&source)
        .map_err(|e| napi::Error::from_reason(format!("Parse error: {e}")))?;
    Ok(dotsec_core::dotenv::lines_to_string(&lines))
}

/// Format a .env file to match schema key ordering.
#[napi]
pub fn format_by_schema(source: String, schema_source: String) -> napi::Result<String> {
    let lines = dotsec_core::dotenv::parse_dotenv(&source)
        .map_err(|e| napi::Error::from_reason(format!("Parse error: {e}")))?;
    let schema = dotsec_core::dotenv::parse_schema(&schema_source)
        .map_err(|e| napi::Error::from_reason(format!("Schema parse error: {e}")))?;
    let formatted = dotsec_core::dotenv::format_lines_by_schema(&lines, &schema);
    Ok(dotsec_core::dotenv::lines_to_string(&formatted))
}

/// Discover the schema file path for a given .sec file.
/// Checks: explicit path → DOTSEC_SCHEMA env var → dotsec.schema in same dir.
/// Returns null if no schema found.
#[napi]
pub fn discover_schema(sec_file_path: String, explicit_schema: Option<String>) -> Option<String> {
    dotsec_core::dotenv::schema::discover_schema(&sec_file_path, explicit_schema.as_deref())
}

/// Load and parse a schema file from disk. Uses discovery if no path given.
/// Returns null if no schema found.
#[napi]
pub fn load_schema(sec_file_path: Option<String>, explicit_schema: Option<String>) -> napi::Result<Option<Vec<ParsedSchemaEntry>>> {
    let sec_path = sec_file_path.as_deref().unwrap_or(".sec");
    let schema_path = dotsec_core::dotenv::schema::discover_schema(sec_path, explicit_schema.as_deref());

    let path = match schema_path {
        Some(p) => p,
        None => return Ok(None),
    };

    let content = std::fs::read_to_string(&path)
        .map_err(|e| napi::Error::from_reason(format!("Failed to read {}: {}", path, e)))?;
    let schema = dotsec_core::dotenv::parse_schema(&content)
        .map_err(|e| napi::Error::from_reason(format!("Schema parse error: {e}")))?;

    Ok(Some(schema
        .entries
        .into_iter()
        .map(|e| ParsedSchemaEntry {
            key: e.key,
            directives: e
                .directives
                .into_iter()
                .map(|(name, value)| DirectiveItem { name, value })
                .collect(),
        })
        .collect()))
}

/// Parse a schema file string and return entries with their directives.
#[napi]
pub fn parse_schema(source: String) -> napi::Result<Vec<ParsedSchemaEntry>> {
    let schema = dotsec_core::dotenv::parse_schema(&source)
        .map_err(|e| napi::Error::from_reason(format!("Schema parse error: {e}")))?;

    Ok(schema
        .entries
        .into_iter()
        .map(|e| ParsedSchemaEntry {
            key: e.key,
            directives: e
                .directives
                .into_iter()
                .map(|(name, value)| DirectiveItem { name, value })
                .collect(),
        })
        .collect())
}

/// Convert a schema file to JSON Schema (draft-07).
#[napi]
pub fn schema_to_json_schema(schema_source: String) -> napi::Result<String> {
    let schema = dotsec_core::dotenv::parse_schema(&schema_source)
        .map_err(|e| napi::Error::from_reason(format!("Schema parse error: {e}")))?;
    let json_schema = dotsec_core::dotenv::schema_to_json_schema(&schema);
    serde_json::to_string_pretty(&json_schema)
        .map_err(|e| napi::Error::from_reason(format!("JSON error: {e}")))
}

/// Generate TypeScript code from a schema file.
#[napi]
pub fn schema_to_typescript(schema_source: String) -> napi::Result<String> {
    let schema = dotsec_core::dotenv::parse_schema(&schema_source)
        .map_err(|e| napi::Error::from_reason(format!("Schema parse error: {e}")))?;
    Ok(dotsec_core::dotenv::schema_to_typescript(&schema))
}
