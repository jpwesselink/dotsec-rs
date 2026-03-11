use clap::parser::ValueSource;
use clap::ValueEnum;
use colored::Colorize;
use log::debug;
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::HashMap;

use crate::constants::AWS_KEY_ID;

#[derive(Clone, Debug, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub struct DotsecConfig {
    // rename to $schema
    /// JSON schema source
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    pub platforms: Option<Platforms>,
    pub command_defaults: Option<CommandDefaults>,
    // pub name: String,
    // pub defaults: Option<Defaults>,
    pub redaction: Option<Redaction>,
    // pub push: Option<Push>,
    // pub plugins: Option<Plugins>,
}

impl DotsecConfig {
    pub fn default() -> DotsecConfig {
        DotsecConfig {
            schema: None,
            platforms: Some(Platforms::default()),
            command_defaults: Some(CommandDefaults::default()),
            redaction: None,
        }
    }
    pub fn set_command_defaults(&mut self, command_defaults: CommandDefaults) {
        self.command_defaults = Some(command_defaults);
    }

    pub fn set_encryption_engine(&mut self, encryption_engine: EncryptionEngine) {
        self.command_defaults.as_mut().unwrap().encryption_engine = Some(encryption_engine);
    }

    pub fn set_env_file(&mut self, env_file: String) {
        self.command_defaults.as_mut().unwrap().env_file = Some(env_file);
    }

    pub fn set_sec_file(&mut self, sec_file: String) {
        self.command_defaults.as_mut().unwrap().sec_file = Some(sec_file);
    }
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub enum Platform {
    #[default]
    Aws,
    Pki,
    None,
}
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub struct Platforms {
    pub aws: Option<AwsEncryptionOptions>,
    pub pki: Option<PkiEncryptionOptions>,
}

impl Platforms {
    pub fn default() -> Platforms {
        Platforms {
            aws: Some(AwsEncryptionOptions::default()),
            pki: Some(PkiEncryptionOptions::default()),
        }
    }
}
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
/// --encryption-engine=aws or DOTSEC_ENCRYPTION_ENGINE=aws
pub struct AwsEncryptionOptions {
    /// --aws-key-id <key_id> or DOTSEC_AWS_KEY_ID
    pub key_id: Option<String>,
    pub secrets_manager: Option<AwsSecretsManager>,
}

impl AwsEncryptionOptions {
    pub fn default() -> AwsEncryptionOptions {
        AwsEncryptionOptions {
            key_id: Some(AWS_KEY_ID.to_string()),
            secrets_manager: None,
        }
    }
}
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
/// --encryption-engine=aws or DOTSEC_ENCRYPTION_ENGINE=aws
pub struct PkiEncryptionOptions {
    /// --aws-key-id <key_id> or DOTSEC_AWS_KEY_ID
    pub key_id: Option<String>,
    pub secrets_manager: Option<AwsSecretsManager>,
}

impl PkiEncryptionOptions {
    pub fn default() -> PkiEncryptionOptions {
        PkiEncryptionOptions {
            key_id: Some(AWS_KEY_ID.to_string()),
            secrets_manager: None,
        }
    }
}
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub struct AwsSecretsManager {
    /// --aws-secrets-manager-change-case <change_case> or DOTSEC_AWS_SECRETS_MANAGER_CHANGE_CASE
    pub change_case: Option<ChangeCase>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]

/// --encryption-engine or DOTSEC_ENCRYPTION_ENGINE
pub enum EncryptionEngine {
    Aws(AwsEncryptionOptions),
    Pki(PkiEncryptionOptions),
    #[default]
    None,
}
#[derive(Clone, Debug, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub struct CommandDefaults {
    pub platform: Option<Platform>,
    /// --encryption-engine or DOTSEC_ENCRYPTION_ENGINE
    pub encryption_engine: Option<EncryptionEngine>,
    /// --env-file <env_file> or DOTSEC_ENV_FILE
    pub env_file: Option<String>,
    /// --sec-file <sec_file> or DOTSEC_SEC_FILE
    pub sec_file: Option<String>,
    pub commands: Option<Commands>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub struct Commands {
    // default to Option<None>
    pub run: Option<Run>,
    pub validate: Option<Validate>,
    pub show: Option<Show>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub struct Run {
    /// run --redaction or DOTSEC_RUN_REDACTION
    pub no_redaction: Option<bool>,
    pub using: Option<RunUsing>,
}

#[derive(Clone, Debug, Deserialize, ValueEnum, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub enum RunUsing {
    #[default]
    Sec,
    Env,
}
#[derive(Clone, Debug, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub struct Validate {
    /// validate --schema <schema> or DOTSEC_VALIDATION_SCHEMA
    pub schema: String,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub struct Show {
    pub target: Option<ShowTarget>,
    pub output_format: Option<OutputFormat>,
}
#[derive(Clone, Debug, Deserialize, ValueEnum, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub enum ShowTarget {
    #[default]
    Sec,
    Env,
}

#[derive(Clone, Debug, Deserialize, ValueEnum, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
#[schemars(deny_unknown_fields)]
pub enum OutputFormat {
    #[default]
    Raw,
    Json,
    Text,
    Csv,
}

// #[derive(Clone, Debug, Deserialize, JsonSchema)]
// #[schemars(deny_unknown_fields)]
// pub struct Defaults {
//     pub options: Option<Options>,
// }

// #[derive(Clone, Debug, Deserialize, JsonSchema)]
// #[schemars(deny_unknown_fields)]
// pub struct Plugins {
//     pub aws: Option<AwsPlugin>,
// }

// #[derive(Clone, Debug, Deserialize, JsonSchema)]
// #[schemars(deny_unknown_fields)]
// pub struct AwsPlugin {
//     #[serde(rename = "secretsManager")]
//     pub secrets_manager: Option<AwsPluginSecretsManager>,
//     // ssm: Option<Ssm>,
// }

// #[derive(Clone, Debug, Deserialize, JsonSchema)]
// #[serde(rename_all = "camelCase")]
// #[schemars(deny_unknown_fields)]
// pub struct AwsPluginSecretsManager {
//     #[serde(rename = "changeCase")]
//     /**
//      * ["camelCase", "capitalCase", "constantCase", "dotCase", "headerCase", "noCase", "paramCase", "pascalCase", "pathCase", "sentenceCase", "snakeCase"]
//      */
//     pub change_case: Option<ChangeCase>,
// }

#[derive(Clone, Debug, Deserialize, ValueEnum, JsonSchema, PartialEq)]
#[schemars(deny_unknown_fields)]
pub enum ChangeCase {
    CamelCase,
    CapitalCase,
    ConstantCase,
    DotCase,
    HeaderCase,
    NoCase,
    ParamCase,
    PascalCase,
    PathCase,
    SentenceCase,
    SnakeCase,
}
#[derive(Clone, Debug, Deserialize, JsonSchema)]
// #[derive(Clone, Debug, Deserialize, ClapSerde, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct Options {
    /// String argument
    #[serde(rename = "envFile")]
    pub env_file: Option<String>,

    #[serde(rename = "secFile")]
    pub sec_file: Option<String>,

    #[serde(rename = "keyId")]
    pub key_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct Redaction {
    /// --redaction-exclude <exclude> or DOTSEC_REDACTION_EXCLUDE
    pub exclude: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct Push {
    pub aws: HashMap<String, Aws>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct Aws {
    #[serde(rename = "secretsManager")]
    pub secrets_manager: bool,
    pub ssm: bool,
}

pub enum DotsecValueSource {
    Env,
    Default,
    Config,
    Arg,
    Not,
}

// add formatter for DotsecValueSource
impl std::fmt::Display for DotsecValueSource {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DotsecValueSource::Env => write!(f, "environment variable"),
            DotsecValueSource::Default => write!(f, "default value"),
            DotsecValueSource::Config => write!(f, "configuration file"),
            DotsecValueSource::Arg => write!(f, "command line argument"),
            DotsecValueSource::Not => write!(f, "not"),
        }
    }
}

// 1. check if env_file is set in the command line
// 2. check if env_file is set in the environment
// 3. check if env_file is set in the config file
// 4. check if env_file is set as a default value
// debug
pub fn get_value_source<'a, T: std::fmt::Debug>(
    value_source: Option<ValueSource>,
    clap_value: Option<&'a T>,
    value: Option<&'a T>,
    name: &str,
) -> Option<&'a T> {
    let (resolved_value, value_source) = if value_source == Some(ValueSource::CommandLine) {
        (clap_value, DotsecValueSource::Arg)
    } else if value_source == Some(ValueSource::EnvVariable) {
        (clap_value, DotsecValueSource::Env)
    } else if value.is_some() {
        (value, DotsecValueSource::Config)
    } else if value_source == Some(ValueSource::DefaultValue) {
        (clap_value, DotsecValueSource::Default)
    } else {
        (None, DotsecValueSource::Not)
    };

    // print value name and value_source
    debug!(
        "Resolved {} from {} {:?}",
        name.bright_yellow(),
        value_source.to_string().cyan(),
        resolved_value
    );

    resolved_value
}
