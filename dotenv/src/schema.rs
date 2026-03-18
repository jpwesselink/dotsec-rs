use std::path::Path;

/// Discover the schema file path for a given .sec file.
///
/// Resolution order:
/// 1. Explicit path from --schema flag
/// 2. DOTSEC_SCHEMA environment variable
/// 3. `dotsec.schema` in same directory as the .sec file
pub fn discover_schema(sec_file_path: &str, explicit: Option<&str>) -> Option<String> {
    // 1. Explicit path
    if let Some(path) = explicit {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
        return None;
    }

    // 2. DOTSEC_SCHEMA env var
    if let Ok(path) = std::env::var("DOTSEC_SCHEMA") {
        if Path::new(&path).exists() {
            return Some(path);
        }
    }

    // 3. dotsec.schema in same directory as .sec file
    let sec_path = Path::new(sec_file_path);
    let dir = sec_path.parent().unwrap_or_else(|| Path::new("."));
    let schema_path = dir.join("dotsec.schema");
    if schema_path.exists() {
        return Some(schema_path.to_string_lossy().to_string());
    }

    None
}
