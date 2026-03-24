use std::path::Path;

/// Discover the schema file path for a given .sec file.
///
/// Resolution order:
/// 1. Explicit path from --schema flag (error if path doesn't exist)
/// 2. DOTSEC_SCHEMA environment variable
/// 3. `dotsec.schema` in same directory as the .sec file
///
/// Returns `Err` if an explicit path was given but does not exist.
pub fn discover_schema(sec_file_path: &str, explicit: Option<&str>) -> Result<Option<String>, String> {
    // 1. Explicit path — error if it doesn't exist
    if let Some(path) = explicit {
        if Path::new(path).exists() {
            return Ok(Some(path.to_string()));
        }
        return Err(format!("schema file not found: {}", path));
    }

    // 2. DOTSEC_SCHEMA env var — error if set but file doesn't exist
    if let Ok(path) = std::env::var("DOTSEC_SCHEMA") {
        if Path::new(&path).exists() {
            return Ok(Some(path));
        }
        return Err(format!("DOTSEC_SCHEMA is set to \"{}\" but file does not exist", path));
    }

    // 3. dotsec.schema in same directory as .sec file
    let sec_path = Path::new(sec_file_path);
    let dir = sec_path.parent().unwrap_or_else(|| Path::new("."));
    let schema_path = dir.join("dotsec.schema");
    if schema_path.exists() {
        return Ok(Some(schema_path.to_string_lossy().to_string()));
    }

    Ok(None)
}
