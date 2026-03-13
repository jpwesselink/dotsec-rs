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

/// Validation error for a specific key.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidationError {
    pub key: String,
    pub message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.key, self.message)
    }
}

/// File-level config directives (not attached to entries).
const FILE_CONFIG_DIRECTIVES: &[&str] = &["provider", "key-id", "region", "default-encrypt", "default-plaintext"];
const KNOWN_DIRECTIVES: &[&str] = &["encrypt", "plaintext", "default-encrypt", "default-plaintext", "type", "push", "description", "provider", "key-id", "region"];
const KNOWN_PUSH_TARGETS: &[&str] = &[
    "aws-ssm", "ssm",
    "aws-secrets-manager", "aws-secretsmanager", "secretsmanager", "secrets-manager",
];
const KNOWN_TYPES: &[&str] = &["string", "number", "boolean", "bool"];

impl Entry {
    pub fn has_directive(&self, name: &str) -> bool {
        self.directives.iter().any(|(n, _)| n == name)
    }

    pub fn get_directive(&self, name: &str) -> Option<&Option<String>> {
        self.directives.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }

    /// Parse `@push` directive into structured push targets.
    pub fn push_targets(&self) -> Vec<PushTarget> {
        match self.get_directive("push") {
            Some(Some(value)) => parse_push_targets(value),
            _ => vec![],
        }
    }

    /// Parse `@type` directive into a VarType.
    pub fn var_type(&self) -> Option<VarType> {
        match self.get_directive("type") {
            Some(Some(value)) => parse_var_type(value),
            _ => None,
        }
    }

    /// Validate all directives and the value on this entry. Returns a list of errors (empty = valid).
    pub fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        for (name, value) in &self.directives {
            if !KNOWN_DIRECTIVES.contains(&name.as_str()) {
                errors.push(ValidationError {
                    key: self.key.clone(),
                    message: format!(
                        "unknown directive @{}. Expected one of: {}",
                        name,
                        KNOWN_DIRECTIVES.join(", ")
                    ),
                });
                continue;
            }

            match name.as_str() {
                "encrypt" | "plaintext" => {
                    if value.is_some() {
                        errors.push(ValidationError {
                            key: self.key.clone(),
                            message: format!("@{} takes no value", name),
                        });
                    }
                }
                n if FILE_CONFIG_DIRECTIVES.contains(&n) => {
                    // File-level directives — should not appear on entries
                    errors.push(ValidationError {
                        key: self.key.clone(),
                        message: format!("@{} is a file-level directive and should not be attached to a variable", name),
                    });
                }
                "type" => {
                    match value {
                        None => {
                            errors.push(ValidationError {
                                key: self.key.clone(),
                                message: format!(
                                    "@type requires a value. Expected one of: {}, or enum(\"value1\", \"value2\")",
                                    KNOWN_TYPES.join(", ")
                                ),
                            });
                        }
                        Some(v) => {
                            if parse_var_type(v).is_none() {
                                let unquoted = v.trim().trim_matches('"');
                                if unquoted.starts_with("enum(") && unquoted.ends_with(')') {
                                    errors.push(ValidationError {
                                        key: self.key.clone(),
                                        message: "enum values must be quoted: @type=enum(\"value1\", \"value2\")".to_string(),
                                    });
                                } else {
                                    errors.push(ValidationError {
                                        key: self.key.clone(),
                                        message: format!(
                                            "invalid type \"{}\". Expected one of: {}, or enum(\"value1\", \"value2\")",
                                            v,
                                            KNOWN_TYPES.join(", ")
                                        ),
                                    });
                                }
                            }
                        }
                    }
                }
                "push" => {
                    match value {
                        None => {
                            errors.push(ValidationError {
                                key: self.key.clone(),
                                message: format!(
                                    "@push requires a value. Expected one of: {}",
                                    KNOWN_PUSH_TARGETS.iter()
                                        .filter(|t| t.starts_with("aws-"))
                                        .cloned()
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ),
                            });
                        }
                        Some(v) => {
                            let targets = parse_push_targets(v);
                            if targets.is_empty() {
                                errors.push(ValidationError {
                                    key: self.key.clone(),
                                    message: format!(
                                        "no valid push targets found in \"{}\". Expected: aws-ssm, aws-secrets-manager. Parameter values must be quoted: aws-ssm(path=\"/my/path\")",
                                        v
                                    ),
                                });
                            }
                        }
                    }
                }
                "description" => {
                    if value.is_none() {
                        errors.push(ValidationError {
                            key: self.key.clone(),
                            message: "@description requires a value".to_string(),
                        });
                    }
                }
                _ => {}
            }
        }

        // Validate the actual value against @type
        if let Some(var_type) = self.var_type() {
            self.validate_value(&var_type, &self.value, &mut errors);
        }

        errors
    }

    /// Validate a value against its declared type.
    pub fn validate_value(&self, var_type: &VarType, value: &str, errors: &mut Vec<ValidationError>) {
        match var_type {
            VarType::Number => {
                if value.parse::<f64>().is_err() {
                    errors.push(ValidationError {
                        key: self.key.clone(),
                        message: format!("expected number, got \"{}\"", value),
                    });
                }
            }
            VarType::Boolean => {
                match value {
                    "true" | "false" | "1" | "0" => {}
                    _ => {
                        errors.push(ValidationError {
                            key: self.key.clone(),
                            message: format!("expected boolean (true/false/1/0), got \"{}\"", value),
                        });
                    }
                }
            }
            VarType::Enum(variants) => {
                if !variants.contains(&value.to_string()) {
                    errors.push(ValidationError {
                        key: self.key.clone(),
                        message: format!(
                            "value \"{}\" not in enum. Expected one of: {}",
                            value,
                            variants.iter().map(|v| format!("\"{}\"", v)).collect::<Vec<_>>().join(", ")
                        ),
                    });
                }
            }
            VarType::String => {} // any value is valid
        }
    }

    /// Validate a value from an environment variable override against this entry's @type.
    pub fn validate_env_override(&self, env_value: &str) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(var_type) = self.var_type() {
            self.validate_value(&var_type, env_value, &mut errors);
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
fn parse_push_targets(value: &str) -> Vec<PushTarget> {
    let mut targets = Vec::new();
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
            "aws-ssm" | "ssm" => {
                targets.push(PushTarget::AwsSsm(SsmOptions {
                    path: params.get("path").cloned(),
                    prefix: params.get("prefix").cloned(),
                }));
            }
            "aws-secrets-manager" | "aws-secretsmanager" | "secretsmanager" | "secrets-manager" => {
                targets.push(PushTarget::AwsSecretsManager(SecretsManagerOptions {
                    path: params.get("path").cloned(),
                }));
            }
            _ => {} // unknown target, skip
        }
    }

    targets
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
