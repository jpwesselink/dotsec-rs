use std::fmt;

#[derive(PartialEq, Clone, Debug)]
pub enum QuoteType {
    Single,
    Double,
    Backtick,
    None,
}

#[derive(Clone, Debug)]
pub enum Line {
    Comment(String),
    Directive(String, Option<String>), // name, optional value
    Kv(String, String, QuoteType),
    Newline,
    Whitespace(String),
}

/// File-level configuration extracted from directives at the top of a .sec file.
#[derive(Clone, Debug, Default)]
pub struct FileConfig {
    pub provider: Option<String>,
    pub key_id: Option<String>,
    pub region: Option<String>,
    pub default_encrypt: Option<bool>,
}

/// A key-value entry with its associated directives and surrounding context.
#[derive(Clone, Debug)]
pub struct Entry {
    pub directives: Vec<(String, Option<String>)>, // (name, optional value)
    pub key: String,
    pub value: String,
    pub quote_type: QuoteType,
}

/// Severity of a validation result.
#[derive(Clone, Debug, PartialEq)]
pub enum Severity {
    Error,
    Warning,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Severity::Error => write!(f, "error"),
            Severity::Warning => write!(f, "warning"),
        }
    }
}

/// Validation error for a specific key.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidationError {
    pub key: String,
    pub message: String,
    pub severity: Severity,
}

impl ValidationError {
    pub fn error(key: impl Into<String>, message: impl Into<String>) -> Self {
        Self { key: key.into(), message: message.into(), severity: Severity::Error }
    }

    pub fn warning(key: impl Into<String>, message: impl Into<String>) -> Self {
        Self { key: key.into(), message: message.into(), severity: Severity::Warning }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.severity {
            Severity::Error => write!(f, "{}: {}", self.key, self.message),
            Severity::Warning => write!(f, "{}: [warning] {}", self.key, self.message),
        }
    }
}

/// File-level config directives (not attached to entries).
const FILE_CONFIG_DIRECTIVES: &[&str] = &["provider", "key-id", "region", "default-encrypt", "default-plaintext"];

/// Per-key directives that belong in a schema file (shared across environments).
pub const SCHEMA_DIRECTIVES: &[&str] = &[
    "type", "push", "encrypt", "plaintext", "format", "pattern",
    "min", "max", "min-length", "max-length",
    "optional", "not-empty", "deprecated", "description",
];

/// File-level directives that are schema-owned (defaults).
pub const SCHEMA_FILE_LEVEL_DIRECTIVES: &[&str] = &["default-encrypt", "default-plaintext"];

/// Environment directives that stay in .sec files.
pub const ENV_DIRECTIVES: &[&str] = &["provider", "key-id", "region"];

// --- Format types ---

#[derive(Clone, Debug, PartialEq)]
pub enum FormatType {
    Email,
    Url,
    Uuid,
    Ipv4,
    Ipv6,
    Date,
    Semver,
}

impl FormatType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "email" => Some(Self::Email),
            "url" => Some(Self::Url),
            "uuid" => Some(Self::Uuid),
            "ipv4" => Some(Self::Ipv4),
            "ipv6" => Some(Self::Ipv6),
            "date" => Some(Self::Date),
            "semver" => Some(Self::Semver),
            _ => None,
        }
    }

    /// Validate a value against this format. Returns an error message if invalid.
    pub fn validate(&self, value: &str) -> Option<String> {
        match self {
            Self::Email => {
                if let Some(at_pos) = value.find('@') {
                    let domain = &value[at_pos + 1..];
                    if let Some(dot_pos) = domain.rfind('.') {
                        if at_pos > 0 && dot_pos > 0 && dot_pos < domain.len() - 1 {
                            return None;
                        }
                    }
                }
                Some(format!("expected email format, got \"{}\"", value))
            }
            Self::Url => {
                if value.starts_with("http://") || value.starts_with("https://") {
                    None
                } else {
                    Some(format!("expected url format (http:// or https://), got \"{}\"", value))
                }
            }
            Self::Uuid => {
                // 8-4-4-4-12 hex pattern
                let parts: Vec<&str> = value.split('-').collect();
                if parts.len() == 5
                    && parts[0].len() == 8
                    && parts[1].len() == 4
                    && parts[2].len() == 4
                    && parts[3].len() == 4
                    && parts[4].len() == 12
                    && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
                {
                    None
                } else {
                    Some(format!("expected uuid format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx), got \"{}\"", value))
                }
            }
            Self::Ipv4 => {
                let parts: Vec<&str> = value.split('.').collect();
                if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
                    None
                } else {
                    Some(format!("expected ipv4 format, got \"{}\"", value))
                }
            }
            Self::Ipv6 => {
                // Basic IPv6 format heuristic — validates colon-separated hex groups
                // but does not enforce RFC 5952.
                let parts: Vec<&str> = value.split(':').collect();
                if parts.len() >= 2
                    && parts.len() <= 8
                    && parts.iter().all(|p| p.is_empty() || (p.len() <= 4 && p.chars().all(|c| c.is_ascii_hexdigit())))
                    && parts.iter().any(|p| !p.is_empty()) // require at least one non-empty group
                {
                    None
                } else {
                    Some(format!("expected ipv6 format, got \"{}\"", value))
                }
            }
            Self::Date => {
                // Basic ISO 8601 date format validation — checks YYYY-MM-DD structure
                // but does not validate calendar correctness (e.g., Feb 31).
                // Simple month-day limits are enforced: months 4,6,9,11 max 30; month 2 max 29.
                let parts: Vec<&str> = value.split('-').collect();
                if parts.len() == 3
                    && parts[0].len() == 4
                    && parts[1].len() == 2
                    && parts[2].len() == 2
                    && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
                {
                    let year: u32 = parts[0].parse().unwrap_or(0);
                    let month: u32 = parts[1].parse().unwrap_or(0);
                    let day: u32 = parts[2].parse().unwrap_or(0);
                    if year > 0 && (1..=12).contains(&month) && day >= 1 {
                        let max_day = match month {
                            2 => 29,
                            4 | 6 | 9 | 11 => 30,
                            _ => 31,
                        };
                        if day <= max_day {
                            return None;
                        }
                    }
                }
                Some(format!("expected date format (YYYY-MM-DD), got \"{}\"", value))
            }
            Self::Semver => {
                // MAJOR.MINOR.PATCH with optional pre-release
                let base = value.split('-').next().unwrap_or(value);
                let parts: Vec<&str> = base.split('.').collect();
                if parts.len() == 3 && parts.iter().all(|p| p.parse::<u64>().is_ok()) {
                    None
                } else {
                    Some(format!("expected semver format (MAJOR.MINOR.PATCH), got \"{}\"", value))
                }
            }
        }
    }
}

/// Trait for types that provide directive access (e.g. `Entry`, `SchemaEntry`).
/// This abstracts over the directive storage so that validation logic can be shared.
pub trait DirectiveSource {
    fn has_directive(&self, name: &str) -> bool;
    fn get_directive(&self, name: &str) -> Option<&Option<String>>;

    fn var_type(&self) -> Option<VarType> {
        match self.get_directive("type") {
            Some(Some(value)) => parse_var_type(value),
            _ => None,
        }
    }

    fn format_type(&self) -> Option<FormatType> {
        match self.get_directive("format") {
            Some(Some(value)) => FormatType::parse(value),
            _ => None,
        }
    }
}

/// Validate a value against its declared type. Returns errors appended to the provided vector.
pub fn validate_value_for_type(key: &str, var_type: &VarType, value: &str, errors: &mut Vec<ValidationError>) {
    match var_type {
        VarType::Number => {
            if value.parse::<f64>().is_err() {
                errors.push(ValidationError::error(
                    key,
                    format!("expected number, got \"{}\"", value),
                ));
            }
        }
        VarType::Boolean => {
            match value {
                "true" | "false" | "1" | "0" => {}
                _ => {
                    errors.push(ValidationError::error(
                        key,
                        format!("expected boolean (true/false/1/0), got \"{}\"", value),
                    ));
                }
            }
        }
        VarType::Enum(variants) => {
            if !variants.contains(&value.to_string()) {
                errors.push(ValidationError::error(
                    key,
                    format!(
                        "value \"{}\" not in enum. Expected one of: {}",
                        value,
                        variants.iter().map(|v| format!("\"{}\"", v)).collect::<Vec<_>>().join(", ")
                    ),
                ));
            }
        }
        VarType::String => {} // any value is valid
    }
}

/// Validate a value against all constraint directives from a `DirectiveSource`.
/// Checks @type, @format, @pattern, @min/@max, @min-length/@max-length, @not-empty, @deprecated.
pub fn validate_value_against_constraints(
    key: &str,
    value: &str,
    source: &dyn DirectiveSource,
) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    let var_type = source.var_type();

    // Validate @type
    if let Some(ref vt) = var_type {
        validate_value_for_type(key, vt, value, &mut errors);
    }

    // Validate @format
    if let Some(format_type) = source.format_type() {
        if let Some(msg) = format_type.validate(value) {
            errors.push(ValidationError::error(key, msg));
        }
    }

    // Validate @pattern
    if let Some(Some(pattern)) = source.get_directive("pattern") {
        if pattern.len() > 1024 {
            errors.push(ValidationError::error(
                key,
                format!(
                    "regex pattern exceeds maximum length of 1024 chars (got {})",
                    pattern.len()
                ),
            ));
        } else {
            match regex::RegexBuilder::new(pattern)
                .size_limit(1 << 20)
                .build()
            {
                Ok(re) => {
                    if !re.is_match(value) {
                        errors.push(ValidationError::error(
                            key,
                            format!("value \"{}\" does not match pattern \"{}\"", value, pattern),
                        ));
                    }
                }
                Err(e) => {
                    errors.push(ValidationError::error(
                        key,
                        format!("invalid regex pattern \"{}\": {}", pattern, e),
                    ));
                }
            }
        }
    }

    // Validate @min / @max (only meaningful with @type=number)
    if let Some(ref var_type) = var_type {
        if *var_type == VarType::Number {
            if let Ok(val) = value.parse::<f64>() {
                if let Some(Some(min_str)) = source.get_directive("min") {
                    match min_str.parse::<f64>() {
                        Ok(min) => {
                            if val < min {
                                errors.push(ValidationError::error(
                                    key,
                                    format!("value {} is less than minimum {}", val, min),
                                ));
                            }
                        }
                        Err(_) => {
                            errors.push(ValidationError::error(
                                key,
                                format!("@min value \"{}\" is not a valid number", min_str),
                            ));
                        }
                    }
                }
                if let Some(Some(max_str)) = source.get_directive("max") {
                    match max_str.parse::<f64>() {
                        Ok(max) => {
                            if val > max {
                                errors.push(ValidationError::error(
                                    key,
                                    format!("value {} is greater than maximum {}", val, max),
                                ));
                            }
                        }
                        Err(_) => {
                            errors.push(ValidationError::error(
                                key,
                                format!("@max value \"{}\" is not a valid number", max_str),
                            ));
                        }
                    }
                }
            }
        }
    }

    // Validate @min-length / @max-length (using char count, not byte count)
    if let Some(Some(min_len_str)) = source.get_directive("min-length") {
        match min_len_str.parse::<usize>() {
            Ok(min_len) => {
                let char_count = value.chars().count();
                if char_count < min_len {
                    errors.push(ValidationError::error(
                        key,
                        format!("value has {} characters, less than minimum length {}", char_count, min_len),
                    ));
                }
            }
            Err(_) => {
                errors.push(ValidationError::error(
                    key,
                    format!("@min-length value \"{}\" is not a valid integer", min_len_str),
                ));
            }
        }
    }
    if let Some(Some(max_len_str)) = source.get_directive("max-length") {
        match max_len_str.parse::<usize>() {
            Ok(max_len) => {
                let char_count = value.chars().count();
                if char_count > max_len {
                    errors.push(ValidationError::error(
                        key,
                        format!("value has {} characters, exceeds maximum length {}", char_count, max_len),
                    ));
                }
            }
            Err(_) => {
                errors.push(ValidationError::error(
                    key,
                    format!("@max-length value \"{}\" is not a valid integer", max_len_str),
                ));
            }
        }
    }

    // Validate @not-empty
    if source.has_directive("not-empty") && value.is_empty() {
        errors.push(ValidationError::error(key, "value must not be empty"));
    }

    // Warn on @deprecated
    if source.has_directive("deprecated") {
        let msg = match source.get_directive("deprecated") {
            Some(Some(message)) => format!("deprecated: {}", message),
            _ => "deprecated".to_string(),
        };
        errors.push(ValidationError::warning(key, msg));
    }

    errors
}

impl DirectiveSource for Entry {
    fn has_directive(&self, name: &str) -> bool {
        self.directives.iter().any(|(n, _)| n == name)
    }

    fn get_directive(&self, name: &str) -> Option<&Option<String>> {
        self.directives.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }
}

impl Entry {
    /// Check if this entry has a directive with the given name.
    pub fn has_directive(&self, name: &str) -> bool {
        <Self as DirectiveSource>::has_directive(self, name)
    }

    /// Get the value of a directive by name.
    pub fn get_directive(&self, name: &str) -> Option<&Option<String>> {
        <Self as DirectiveSource>::get_directive(self, name)
    }

    /// Parse `@push` directive into structured push targets.
    pub fn push_targets(&self) -> Vec<PushTarget> {
        match self.get_directive("push") {
            Some(Some(value)) => parse_push_targets(value).0,
            _ => vec![],
        }
    }

    /// Parse `@type` directive into a VarType.
    pub fn var_type(&self) -> Option<VarType> {
        <Self as DirectiveSource>::var_type(self)
    }

    /// Parse `@format` directive into a FormatType.
    pub fn format_type(&self) -> Option<FormatType> {
        <Self as DirectiveSource>::format_type(self)
    }

    /// Validate directives and value on this entry. Returns a list of errors (empty = valid).
    ///
    /// Note: Most directive syntax validation is handled by the grammar at parse time.
    /// This method checks semantic constraints that the grammar cannot enforce:
    /// - File-level directives appearing on entries
    /// - Value conformance to declared @type
    /// - Value conformance to @format, @pattern, @min/@max, @min-length/@max-length, @not-empty
    /// - @deprecated warnings
    pub fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        for (name, _value) in &self.directives {
            if FILE_CONFIG_DIRECTIVES.contains(&name.as_str()) {
                errors.push(ValidationError::error(
                    &self.key,
                    format!("@{} is a file-level directive and should not be attached to a variable", name),
                ));
            }
        }

        errors.extend(validate_value_against_constraints(&self.key, &self.value, self));

        // Validate @push targets — report unknown target names (Entry-specific, not in schema)
        if let Some(Some(push_value)) = self.get_directive("push") {
            let (_, unknown_targets) = parse_push_targets(push_value);
            for target in &unknown_targets {
                errors.push(ValidationError::error(
                    &self.key,
                    format!("unknown push target \"{}\"", target),
                ));
            }
        }

        errors
    }

    /// Validate a value against its declared type.
    pub fn validate_value(&self, var_type: &VarType, value: &str, errors: &mut Vec<ValidationError>) {
        validate_value_for_type(&self.key, var_type, value, errors);
    }

    /// Validate a value from an environment variable override against this entry's @type.
    pub fn validate_env_override(&self, env_value: &str) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(var_type) = self.var_type() {
            validate_value_for_type(&self.key, &var_type, env_value, &mut errors);
            // Rewrite messages to indicate it's an env override
            for error in &mut errors {
                error.message = format!("env override: {}", error.message);
            }
        }
        errors
    }
}

// --- Push target types ---

#[derive(Clone, Debug, PartialEq)]
pub enum PushTarget {
    AwsSsm(SsmOptions),
    AwsSecretsManager(SecretsManagerOptions),
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct SsmOptions {
    pub path: Option<String>,
    pub prefix: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Default)]
pub struct SecretsManagerOptions {
    pub path: Option<String>,
}

/// Parse a push directive value like "aws-ssm(path="/myapp/prod"), aws-secrets-manager"
/// Returns (targets, errors) — errors contains unknown target names.
fn parse_push_targets(value: &str) -> (Vec<PushTarget>, Vec<String>) {
    let mut targets = Vec::new();
    let mut errors = Vec::new();
    let mut chars = value.chars().peekable();

    while chars.peek().is_some() {
        // skip whitespace and commas
        while chars.peek().is_some_and(|c| *c == ' ' || *c == ',') {
            chars.next();
        }

        // read target name using peek so we don't consume the delimiter
        let mut name = String::new();
        while chars.peek().is_some_and(|c| c.is_alphanumeric() || *c == '-' || *c == '_') {
            name.push(chars.next().unwrap());
        }

        if name.is_empty() {
            break;
        }

        // check for params in parens
        let params = if chars.peek() == Some(&'(') {
            chars.next(); // consume '('
            let mut params_str = String::new();
            while chars.peek().is_some_and(|c| *c != ')') {
                params_str.push(chars.next().unwrap());
            }
            chars.next(); // consume ')'
            parse_params(&params_str)
        } else {
            std::collections::HashMap::new()
        };

        match name.as_str() {
            "aws-ssm" => {
                targets.push(PushTarget::AwsSsm(SsmOptions {
                    path: params.get("path").cloned(),
                    prefix: params.get("prefix").cloned(),
                }));
            }
            "aws-secrets-manager" => {
                targets.push(PushTarget::AwsSecretsManager(SecretsManagerOptions {
                    path: params.get("path").cloned(),
                }));
            }
            _ => {
                errors.push(name);
            }
        }
    }

    (targets, errors)
}

/// Parse key="value", key2="value2" from inside parens.
/// Values MUST be quoted with double quotes.
fn parse_params(s: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let mut chars = s.chars().peekable();

    loop {
        // skip whitespace and commas
        while chars.peek().is_some_and(|c| *c == ' ' || *c == ',') {
            chars.next();
        }

        if chars.peek().is_none() {
            break;
        }

        // read key
        let mut key = String::new();
        while chars.peek().is_some_and(|c| c.is_alphanumeric() || *c == '_' || *c == '-') {
            key.push(chars.next().unwrap());
        }

        if key.is_empty() {
            break;
        }

        // expect =
        if chars.peek() != Some(&'=') {
            break;
        }
        chars.next(); // consume '='

        // expect opening "
        if chars.peek() != Some(&'"') {
            break; // value must be quoted
        }
        chars.next(); // consume opening "

        // read until closing "
        let mut value = String::new();
        while chars.peek().is_some_and(|c| *c != '"') {
            value.push(chars.next().unwrap());
        }
        chars.next(); // consume closing "

        map.insert(key, value);
    }

    map
}

/// Parse a comma-separated list of quoted strings from inside parens.
/// e.g. `"development", "preview", "production"` -> vec!["development", "preview", "production"]
fn parse_quoted_list(s: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut chars = s.chars().peekable();

    loop {
        // skip whitespace and commas
        while chars.peek().is_some_and(|c| *c == ' ' || *c == ',') {
            chars.next();
        }

        if chars.peek().is_none() {
            break;
        }

        // expect opening "
        if chars.peek() != Some(&'"') {
            break;
        }
        chars.next(); // consume opening "

        // read until closing "
        let mut value = String::new();
        while chars.peek().is_some_and(|c| *c != '"') {
            value.push(chars.next().unwrap());
        }
        chars.next(); // consume closing "

        items.push(value);
    }

    items
}

// --- VarType ---

#[derive(Clone, Debug, PartialEq)]
pub enum VarType {
    String,
    Number,
    Boolean,
    Enum(Vec<String>),
}

// --- Schema types ---

/// A schema entry: a key with its associated directives (no value).
#[derive(Clone, Debug)]
pub struct SchemaEntry {
    pub directives: Vec<(String, Option<String>)>,
    pub key: String,
}

impl DirectiveSource for SchemaEntry {
    fn has_directive(&self, name: &str) -> bool {
        self.directives.iter().any(|(n, _)| n == name)
    }

    fn get_directive(&self, name: &str) -> Option<&Option<String>> {
        self.directives.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }
}

impl SchemaEntry {
    /// Check if this entry has a directive with the given name.
    pub fn has_directive(&self, name: &str) -> bool {
        <Self as DirectiveSource>::has_directive(self, name)
    }

    /// Get the value of a directive by name.
    pub fn get_directive(&self, name: &str) -> Option<&Option<String>> {
        <Self as DirectiveSource>::get_directive(self, name)
    }

    /// Parse `@type` directive into a VarType.
    pub fn var_type(&self) -> Option<VarType> {
        <Self as DirectiveSource>::var_type(self)
    }

    /// Parse `@format` directive into a FormatType.
    pub fn format_type(&self) -> Option<FormatType> {
        <Self as DirectiveSource>::format_type(self)
    }

    /// Whether this key is optional (has `@optional` directive).
    pub fn is_optional(&self) -> bool {
        self.has_directive("optional")
    }

    /// Whether this key is required (not optional).
    pub fn is_required(&self) -> bool {
        !self.is_optional()
    }

    /// Get the `@description` directive value.
    pub fn description(&self) -> Option<&str> {
        match self.get_directive("description") {
            Some(Some(value)) => Some(value.as_str()),
            _ => None,
        }
    }

    /// Get the `@deprecated` directive message (if any).
    pub fn deprecated_message(&self) -> Option<Option<&str>> {
        if !self.has_directive("deprecated") {
            return None;
        }
        match self.get_directive("deprecated") {
            Some(Some(value)) => Some(Some(value.as_str())),
            _ => Some(None),
        }
    }

    /// Get the `@pattern` directive value.
    pub fn pattern(&self) -> Option<&str> {
        match self.get_directive("pattern") {
            Some(Some(value)) => Some(value.as_str()),
            _ => None,
        }
    }

    /// Get a numeric directive value as f64.
    fn numeric_directive(&self, name: &str) -> Option<f64> {
        match self.get_directive(name) {
            Some(Some(value)) => match value.parse() {
                Ok(v) => Some(v),
                Err(_) => {
                    eprintln!("warning: @{} value \"{}\" on key \"{}\" is not a valid number", name, value, self.key);
                    None
                }
            },
            _ => None,
        }
    }

    pub fn min(&self) -> Option<f64> { self.numeric_directive("min") }
    pub fn max(&self) -> Option<f64> { self.numeric_directive("max") }
    pub fn min_length(&self) -> Option<usize> { self.numeric_directive("min-length").map(|v| v as usize) }
    pub fn max_length(&self) -> Option<usize> { self.numeric_directive("max-length").map(|v| v as usize) }
}

/// A parsed schema file.
#[derive(Clone, Debug)]
pub struct Schema {
    pub entries: Vec<SchemaEntry>,
}

impl Schema {
    pub fn get(&self, key: &str) -> Option<&SchemaEntry> {
        self.entries.iter().find(|e| e.key == key)
    }

    pub fn keys(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.key.as_str()).collect()
    }
}

// --- Diff types ---

#[derive(Clone, Debug, PartialEq)]
pub enum DiffItem {
    /// Key exists in base but not in target
    MissingKey { key: String },
    /// Key exists in target but not in base
    ExtraKey { key: String },
    /// Same key, different directives
    DirectiveMismatch {
        key: String,
        base_directives: Vec<(String, Option<String>)>,
        target_directives: Vec<(String, Option<String>)>,
    },
    /// Same key, different value (non-encrypted only)
    ValueDifference {
        key: String,
        base_value: String,
        target_value: String,
    },
    /// Key appears in a different position
    OrderingDifference {
        key: String,
        base_index: usize,
        target_index: usize,
    },
}

impl fmt::Display for DiffItem {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DiffItem::MissingKey { key } => {
                write!(f, "{} exists in base but not in target", key)
            }
            DiffItem::ExtraKey { key } => {
                write!(f, "{} exists in target but not in base", key)
            }
            DiffItem::DirectiveMismatch { key, base_directives, target_directives } => {
                let base_str = format_directives(base_directives);
                let target_str = format_directives(target_directives);
                write!(f, "directive mismatch on {}: base [{}] vs target [{}]", key, base_str, target_str)
            }
            DiffItem::ValueDifference { key, base_value, target_value } => {
                write!(f, "value difference on {}: \"{}\" vs \"{}\"", key, base_value, target_value)
            }
            DiffItem::OrderingDifference { key, base_index, target_index } => {
                write!(f, "ordering difference: {} is at position {} in base, {} in target", key, base_index + 1, target_index + 1)
            }
        }
    }
}

fn format_directives(directives: &[(String, Option<String>)]) -> String {
    directives
        .iter()
        .map(|(name, value)| match value {
            Some(v) => format!("@{}={}", name, v),
            None => format!("@{}", name),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn parse_var_type(value: &str) -> Option<VarType> {
    let trimmed = value.trim();
    // strip optional quotes around simple types: @type="string" or @type=string
    let unquoted = trimmed.trim_matches('"');
    match unquoted {
        "string" => Some(VarType::String),
        "number" => Some(VarType::Number),
        "boolean" | "bool" => Some(VarType::Boolean),
        s if s.starts_with("enum(") && s.ends_with(')') => {
            let inner = &s[5..s.len() - 1];
            let variants = parse_quoted_list(inner);
            if variants.is_empty() {
                None // enum values must be quoted
            } else {
                Some(VarType::Enum(variants))
            }
        }
        _ => None,
    }
}
