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
}

/// Parse a .env file string and return entries with their directives.
#[napi]
pub fn parse(source: String) -> napi::Result<Vec<ParsedEntry>> {
    let lines = dotenv::parse_dotenv(&source)
        .map_err(|e| napi::Error::from_reason(format!("Parse error: {e}")))?;
    let entries = dotenv::lines_to_entries(&lines);

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
    let lines = dotenv::parse_dotenv(&source)
        .map_err(|e| napi::Error::from_reason(format!("Parse error: {e}")))?;
    let entries = dotenv::lines_to_entries(&lines);
    let errors = dotenv::validate_entries(&entries);

    Ok(errors
        .into_iter()
        .map(|e| ParsedValidationError {
            key: e.key,
            message: e.message,
        })
        .collect())
}

/// Convert a .env file string to JSON.
#[napi]
pub fn to_json(source: String) -> napi::Result<String> {
    let lines = dotenv::parse_dotenv(&source)
        .map_err(|e| napi::Error::from_reason(format!("Parse error: {e}")))?;
    dotenv::lines_to_json(&lines).map_err(|e| napi::Error::from_reason(format!("JSON error: {e}")))
}

/// Roundtrip: parse a .env file string and serialize it back.
#[napi]
pub fn format(source: String) -> napi::Result<String> {
    let lines = dotenv::parse_dotenv(&source)
        .map_err(|e| napi::Error::from_reason(format!("Parse error: {e}")))?;
    Ok(dotenv::lines_to_string(&lines))
}
