use clap::{Arg, Command};
use colored::Colorize;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

use crate::cli::helpers::{self, with_progress};
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("migrate")
        .about("Migrate from dotsec v4 config (dotsec.config.ts) to v5 .sec format")
        .arg(
            Arg::new("env-file")
                .help("Path to .env file with plaintext values")
                .env("ENV_FILE")
                .default_value(".env"),
        )
        .arg(
            Arg::new("config")
                .long("config")
                .short('c')
                .help("Path to dotsec v4 config file")
                .default_value("dotsec.config.ts"),
        )
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sub = match matches.subcommand_matches("migrate") {
        Some(m) => m,
        None => return Ok(()),
    };

    let env_file = sub.get_one::<String>("env-file").unwrap();
    let config_file = sub.get_one::<String>("config").unwrap();
    let sec_file = default_options.sec_file;

    // Validate inputs exist
    if !std::path::Path::new(env_file).exists() {
        return Err(format!("{} not found", env_file).into());
    }
    if !std::path::Path::new(config_file).exists() {
        return Err(format!("{} not found", config_file).into());
    }

    // Check if .sec already exists
    if std::path::Path::new(sec_file).exists() {
        let overwrite = inquire::Confirm::new(&format!("{} already exists. Overwrite?", sec_file))
            .with_default(false)
            .prompt()?;
        if !overwrite {
            println!("Aborted.");
            return Ok(());
        }
    }

    // --- Step 1: Parse v4 config via npx tsx / node ---
    println!(
        "{} Reading v4 config from {}",
        "→".dimmed(),
        config_file.bold()
    );
    let v4_config = load_v4_config(config_file)?;

    // --- Step 2: Parse .env file ---
    let content = std::fs::read_to_string(env_file)?;
    let lines = dotenv::parse_dotenv(&content)?;
    let entries = dotenv::lines_to_entries(&lines);

    if entries.is_empty() {
        return Err(format!("{} has no variables", env_file).into());
    }

    // --- Step 3: Extract settings from v4 config ---
    let aws_plugin = v4_config
        .defaults
        .as_ref()
        .and_then(|d| d.plugins.as_ref())
        .and_then(|p| p.aws.as_ref());

    let key_alias = aws_plugin
        .and_then(|a| a.kms.as_ref())
        .and_then(|k| k.key_alias.as_deref())
        .unwrap_or("alias/dotsec");

    let ssm_defaults = aws_plugin.and_then(|a| a.ssm.as_ref());
    let sm_defaults = aws_plugin.and_then(|a| a.secrets_manager.as_ref());

    let show_set: HashSet<&str> = v4_config
        .redaction
        .as_ref()
        .and_then(|r| r.show.as_ref())
        .map(|v| v.iter().map(|s| s.as_str()).collect())
        .unwrap_or_default();

    let push_map = v4_config.push.as_ref();

    // --- Step 4: Build file-level config ---
    let region = aws_plugin
        .and_then(|a| a.kms.as_ref())
        .and_then(|_| {
            // v4 doesn't store region in kms config, try env
            std::env::var("AWS_REGION")
                .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                .ok()
        });

    let file_config = dotenv::FileConfig {
        provider: Some("aws".to_string()),
        key_id: Some(key_alias.to_string()),
        region,
        default_encrypt: Some(true),
    };

    let encryption_engine = dotsec::EncryptionEngine::from(file_config.clone());

    // --- Step 5: Build output lines ---
    let config_lines = helpers::build_config_directives(&file_config, true);
    let mut new_lines: Vec<dotenv::Line> = Vec::new();

    // File-level config directives
    new_lines.extend(config_lines);
    new_lines.push(dotenv::Line::Newline);

    // Stats
    let mut count_encrypt = 0;
    let mut count_plaintext = 0;
    let mut count_push_ssm = 0;
    let mut count_push_sm = 0;

    // Process each line from the .env, preserving comments and structure
    for line in &lines {
        match line {
            dotenv::Line::Directive(_, _) => {
                // Skip old directives — we generate new ones
                continue;
            }

            dotenv::Line::Comment(_) | dotenv::Line::Whitespace(_) | dotenv::Line::Newline => {
                new_lines.push(line.clone());
            }

            dotenv::Line::Kv(key, value, quote_type) => {
                let mut directives: Vec<dotenv::Line> = Vec::new();

                // Encrypt or plaintext?
                // If the var is in redaction.show AND doesn't look like a secret → plaintext
                // Otherwise → encrypt (default-encrypt handles it, but add @plaintext for exceptions)
                let is_plaintext = show_set.contains(key.as_str()) && !helpers::looks_like_secret(key);

                if is_plaintext {
                    directives.push(dotenv::Line::Directive("plaintext".to_string(), None));
                    count_plaintext += 1;
                } else {
                    count_encrypt += 1;
                }

                // Type detection
                let type_name = match helpers::guess_type(value) {
                    1 => "number",
                    2 => "boolean",
                    _ => "string",
                };
                directives.push(dotenv::Line::Directive(
                    "type".to_string(),
                    Some(type_name.to_string()),
                ));

                // Push targets from v4 config
                if let Some(push) = push_map.and_then(|m| m.get(key.as_str())) {
                    let push_value = build_push_directive(key, push, ssm_defaults, sm_defaults);
                    if let Some(pv) = push_value {
                        directives.push(dotenv::Line::Directive("push".to_string(), Some(pv)));
                        if push.aws.as_ref().is_some_and(|a| a.ssm.unwrap_or(false)) {
                            count_push_ssm += 1;
                        }
                        if push
                            .aws
                            .as_ref()
                            .is_some_and(|a| a.secrets_manager.unwrap_or(false))
                        {
                            count_push_sm += 1;
                        }
                    }
                }

                // Emit directives then the KV line
                if !directives.is_empty() {
                    new_lines.extend(directives);
                    new_lines.push(dotenv::Line::Newline);
                }
                new_lines.push(dotenv::Line::Kv(
                    key.clone(),
                    value.clone(),
                    quote_type.clone(),
                ));
                new_lines.push(dotenv::Line::Newline);
            }
        }
    }

    // --- Step 6: Encrypt and write ---
    println!(
        "\n{} {} variables: {} encrypted, {} plaintext",
        "→".dimmed(),
        entries.len(),
        count_encrypt,
        count_plaintext
    );
    if count_push_ssm > 0 || count_push_sm > 0 {
        println!(
            "{} Push targets: {} SSM, {} Secrets Manager",
            "→".dimmed(),
            count_push_ssm,
            count_push_sm
        );
    }

    with_progress(
        "Encrypting...",
        dotsec::encrypt_lines_to_sec(&new_lines, sec_file, &encryption_engine),
    )
    .await?;

    println!(
        "\n{} Migrated {} variables from {} + {} into {}",
        "✓".green(),
        entries.len(),
        env_file,
        config_file,
        sec_file.bold()
    );

    Ok(())
}

/// Load a dotsec v4 config file by shelling out to npx tsx (for TS) or node (for JS).
fn load_v4_config(config_path: &str) -> Result<DotsecV4Config, Box<dyn std::error::Error>> {
    let abs_path = std::fs::canonicalize(config_path)?;
    let abs_str = abs_path.to_string_lossy();

    // Determine runner based on file extension
    let ext = std::path::Path::new(config_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let eval_script = format!(
        "import('file://{}').then(m => {{ const c = m.dotsec ?? m.default?.dotsec ?? m.default; process.stdout.write(JSON.stringify(c)); }})",
        abs_str
    );

    let strategies: Vec<(&str, Vec<String>)> = match ext {
        "ts" | "mts" | "cts" | "tsx" => vec![
            ("npx", vec!["tsx@latest".into(), "-e".into(), eval_script.clone()]),
        ],
        "js" | "mjs" | "cjs" => vec![
            ("node", vec!["-e".into(), eval_script.clone()]),
        ],
        _ => {
            // Try parsing as JSON directly
            let content = std::fs::read_to_string(config_path)?;
            let config: DotsecV4Config = serde_json::from_str(&content)?;
            return Ok(config);
        }
    };

    let mut last_err = String::new();
    let mut output = None;

    for (runner, args) in &strategies {
        match std::process::Command::new(runner).args(args).output() {
            Ok(o) if o.status.success() => {
                output = Some(o);
                break;
            }
            Ok(o) => {
                last_err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            }
            Err(e) => {
                last_err = format!("{}: {}", runner, e);
            }
        }
    }

    let output = output.ok_or_else(|| {
        format!("Failed to parse {} — is Node.js/tsx installed? Last error: {}", config_path, last_err)
    })?;

    let json_str = String::from_utf8(output.stdout)?;
    let config: DotsecV4Config = serde_json::from_str(&json_str).map_err(|e| {
        format!(
            "Failed to parse config JSON: {}. Raw output: {}",
            e,
            helpers::truncate_value(&json_str, 200)
        )
    })?;

    Ok(config)
}

/// Build the @push directive value string for a variable.
/// Computes SSM/SecretsManager paths using v4 defaults (pathPrefix, changeCase).
fn build_push_directive(
    key: &str,
    push: &V4PushEntry,
    ssm_defaults: Option<&V4SsmConfig>,
    sm_defaults: Option<&V4SecretsManagerConfig>,
) -> Option<String> {
    let aws = push.aws.as_ref()?;
    let mut targets: Vec<String> = Vec::new();

    if aws.ssm.unwrap_or(false) {
        let path = compute_push_path(key, ssm_defaults.map(|s| PushDefaults {
            path_prefix: s.path_prefix.as_deref(),
            change_case: s.change_case.as_deref(),
        }));
        match path {
            Some(p) => targets.push(format!("aws-ssm(path=\"{}\")", p)),
            None => targets.push("aws-ssm".to_string()),
        }
    }

    if aws.secrets_manager.unwrap_or(false) {
        let path = compute_push_path(key, sm_defaults.map(|s| PushDefaults {
            path_prefix: s.path_prefix.as_deref(),
            change_case: s.change_case.as_deref(),
        }));
        match path {
            Some(p) => targets.push(format!("aws-secrets-manager(path=\"{}\")", p)),
            None => targets.push("aws-secrets-manager".to_string()),
        }
    }

    if targets.is_empty() {
        None
    } else {
        Some(targets.join(", "))
    }
}

struct PushDefaults<'a> {
    path_prefix: Option<&'a str>,
    change_case: Option<&'a str>,
}

/// Compute the full push path for a variable, applying pathPrefix and changeCase.
fn compute_push_path(key: &str, defaults: Option<PushDefaults<'_>>) -> Option<String> {
    let defaults = defaults?;
    let prefix = defaults.path_prefix?;

    let converted_key = match defaults.change_case {
        Some("camelCase") => screaming_snake_to_camel(key),
        _ => key.to_string(),
    };

    Some(format!("{}{}", prefix, converted_key))
}

/// Convert SCREAMING_SNAKE_CASE to camelCase.
/// e.g. JEDI_YODA_GRAPHQL_ADMIN_SECRET → jediYodaGraphqlAdminSecret
fn screaming_snake_to_camel(s: &str) -> String {
    let mut result = String::new();
    for (i, part) in s.split('_').enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            result.push_str(&part.to_lowercase());
        } else {
            let lower = part.to_lowercase();
            let mut chars = lower.chars();
            if let Some(first) = chars.next() {
                result.extend(first.to_uppercase());
                result.extend(chars);
            }
        }
    }
    result
}

// --- Serde structs for dotsec v4 config ---

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DotsecV4Config {
    defaults: Option<V4Defaults>,
    redaction: Option<V4Redaction>,
    push: Option<HashMap<String, V4PushEntry>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct V4Defaults {
    #[allow(dead_code)]
    encryption_engine: Option<String>,
    plugins: Option<V4Plugins>,
}

#[derive(Debug, Deserialize)]
struct V4Plugins {
    aws: Option<V4AwsPlugin>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct V4AwsPlugin {
    ssm: Option<V4SsmConfig>,
    secrets_manager: Option<V4SecretsManagerConfig>,
    kms: Option<V4KmsConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct V4SsmConfig {
    change_case: Option<String>,
    path_prefix: Option<String>,
    #[serde(rename = "type")]
    #[allow(dead_code)]
    param_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct V4SecretsManagerConfig {
    change_case: Option<String>,
    path_prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct V4KmsConfig {
    key_alias: Option<String>,
}

#[derive(Debug, Deserialize)]
struct V4Redaction {
    show: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct V4PushEntry {
    aws: Option<V4AwsPush>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct V4AwsPush {
    ssm: Option<bool>,
    secrets_manager: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_screaming_snake_to_camel() {
        assert_eq!(screaming_snake_to_camel("HELLO"), "hello");
        assert_eq!(screaming_snake_to_camel("HELLO_WORLD"), "helloWorld");
        assert_eq!(
            screaming_snake_to_camel("JEDI_YODA_GRAPHQL_ADMIN_SECRET"),
            "jediYodaGraphqlAdminSecret"
        );
        assert_eq!(screaming_snake_to_camel("A"), "a");
        assert_eq!(screaming_snake_to_camel("A_B_C"), "aBC");
        assert_eq!(screaming_snake_to_camel("AWS_REGION"), "awsRegion");
    }

    #[test]
    fn test_v4_config_parsing() {
        let json = r#"{
            "defaults": {
                "encryptionEngine": "aws",
                "plugins": {
                    "aws": {
                        "ssm": {
                            "changeCase": "camelCase",
                            "pathPrefix": "/pathehome/",
                            "type": "String"
                        },
                        "secretsManager": {
                            "changeCase": "camelCase",
                            "pathPrefix": "/pathehome/"
                        },
                        "kms": {
                            "keyAlias": "alias/dotsec"
                        }
                    }
                }
            },
            "redaction": {
                "show": ["AWS_REGION", "LOG_RETENTION_DAYS"]
            },
            "push": {
                "DRM_SECRET": {
                    "aws": { "secretsManager": true }
                },
                "JEDI_YODA_GRAPHQL_ADMIN_SECRET": {
                    "aws": { "ssm": true }
                }
            }
        }"#;

        let config: DotsecV4Config = serde_json::from_str(json).unwrap();

        assert_eq!(
            config.defaults.as_ref().unwrap().encryption_engine.as_deref(),
            Some("aws")
        );

        let aws = config
            .defaults
            .as_ref()
            .unwrap()
            .plugins
            .as_ref()
            .unwrap()
            .aws
            .as_ref()
            .unwrap();
        assert_eq!(aws.kms.as_ref().unwrap().key_alias.as_deref(), Some("alias/dotsec"));
        assert_eq!(aws.ssm.as_ref().unwrap().path_prefix.as_deref(), Some("/pathehome/"));
        assert_eq!(aws.ssm.as_ref().unwrap().change_case.as_deref(), Some("camelCase"));

        let show = config.redaction.as_ref().unwrap().show.as_ref().unwrap();
        assert_eq!(show.len(), 2);
        assert!(show.contains(&"AWS_REGION".to_string()));

        let push = config.push.as_ref().unwrap();
        assert!(push["DRM_SECRET"]
            .aws
            .as_ref()
            .unwrap()
            .secrets_manager
            .unwrap());
        assert!(push["JEDI_YODA_GRAPHQL_ADMIN_SECRET"]
            .aws
            .as_ref()
            .unwrap()
            .ssm
            .unwrap());
    }

    #[test]
    fn test_build_push_directive() {
        let ssm_defaults = V4SsmConfig {
            change_case: Some("camelCase".to_string()),
            path_prefix: Some("/pathehome/".to_string()),
            param_type: Some("String".to_string()),
        };

        let sm_defaults = V4SecretsManagerConfig {
            change_case: Some("camelCase".to_string()),
            path_prefix: Some("/pathehome/".to_string()),
        };

        // SSM only
        let push = V4PushEntry {
            aws: Some(V4AwsPush {
                ssm: Some(true),
                secrets_manager: None,
            }),
        };
        let result = build_push_directive(
            "JEDI_YODA_GRAPHQL_ADMIN_SECRET",
            &push,
            Some(&ssm_defaults),
            Some(&sm_defaults),
        );
        assert_eq!(
            result.unwrap(),
            "aws-ssm(path=\"/pathehome/jediYodaGraphqlAdminSecret\")"
        );

        // Secrets Manager only
        let push = V4PushEntry {
            aws: Some(V4AwsPush {
                ssm: None,
                secrets_manager: Some(true),
            }),
        };
        let result = build_push_directive("DRM_SECRET", &push, Some(&ssm_defaults), Some(&sm_defaults));
        assert_eq!(
            result.unwrap(),
            "aws-secrets-manager(path=\"/pathehome/drmSecret\")"
        );

        // Both
        let push = V4PushEntry {
            aws: Some(V4AwsPush {
                ssm: Some(true),
                secrets_manager: Some(true),
            }),
        };
        let result = build_push_directive("MY_VAR", &push, Some(&ssm_defaults), Some(&sm_defaults));
        assert_eq!(
            result.unwrap(),
            "aws-ssm(path=\"/pathehome/myVar\"), aws-secrets-manager(path=\"/pathehome/myVar\")"
        );
    }
}
