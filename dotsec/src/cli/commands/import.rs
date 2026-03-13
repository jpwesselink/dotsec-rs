use clap::{Arg, Command};
use colored::Colorize;
use inquire::Select;

use crate::cli::helpers;
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("import")
        .about("Import a .env file into .sec (one-time migration)")
        .arg(
            Arg::new("env-file")
                .help("Path to .env file to import")
                .default_value(".env"),
        )
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sub = match matches.subcommand_matches("import") {
        Some(m) => m,
        None => return Ok(()),
    };

    let env_file = sub.get_one::<String>("env-file").unwrap();
    let sec_file = default_options.sec_file;
    let encryption_engine = &default_options.encryption_engine;

    if !std::path::Path::new(env_file).exists() {
        return Err(format!("{} not found", env_file).into());
    }

    let content = std::fs::read_to_string(env_file)?;
    let lines = dotenv::parse_dotenv(&content)?;
    let entries = dotenv::lines_to_entries(&lines);
    let source_config = dotenv::extract_file_config(&lines);

    if entries.is_empty() {
        return Err(format!("{} has no variables", env_file).into());
    }

    // Check for existing .sec and determine import mode
    let mut skip_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    let sec_exists = std::path::Path::new(sec_file).exists();
    let existing_config: Option<dotenv::FileConfig>;

    if sec_exists {
        let sec_content = std::fs::read_to_string(sec_file)?;
        let sec_lines = dotenv::parse_dotenv(&sec_content)?;
        let sec_entries = dotenv::lines_to_entries(&sec_lines);
        let sec_config = dotenv::extract_file_config(&sec_lines);
        let existing_keys: std::collections::HashSet<String> =
            sec_entries.iter().map(|e| e.key.clone()).collect();

        let new_count = entries.iter().filter(|e| !existing_keys.contains(&e.key)).count();
        let existing_count = entries.iter().filter(|e| existing_keys.contains(&e.key)).count();

        if new_count == 0 {
            println!("All {} variables already exist in {}, nothing to import.", entries.len(), sec_file);
            return Ok(());
        }

        if existing_count > 0 {
            let options = vec![
                format!("New variables only ({} new, skip {} existing)", new_count, existing_count),
                "Overwrite all".to_string(),
                "Cancel".to_string(),
            ];

            let mode = Select::new(
                &format!("{} already exists. Import mode?", sec_file),
                options,
            )
            .prompt()?;

            if mode.starts_with("Cancel") {
                println!("Aborted.");
                return Ok(());
            }

            if mode.starts_with("New variables only") {
                skip_keys = existing_keys;
            }
        }

        // Check for config conflicts between source .env and existing .sec
        if source_config.provider.is_some() || source_config.key_id.is_some() || source_config.region.is_some() || source_config.default_encrypt.is_some() {
            let diffs = helpers::config_diffs(&source_config, &sec_config);
            if !diffs.is_empty() {
                println!("\n{} Config differences between {} and {}:", "!".yellow().bold(), env_file, sec_file);
                for diff in &diffs {
                    println!("  {} {}", "•".yellow(), diff);
                }
                println!();

                let choice = Select::new(
                    "Which config to use?",
                    vec![
                        format!("Keep {} (existing)", sec_file),
                        format!("Use {} (source)", env_file),
                        "Cancel".to_string(),
                    ],
                )
                .prompt()?;

                if choice.starts_with("Cancel") {
                    println!("Aborted.");
                    return Ok(());
                }

                if choice.starts_with("Use") {
                    existing_config = Some(source_config.clone());
                } else {
                    existing_config = Some(sec_config);
                }
            } else {
                existing_config = Some(sec_config);
            }
        } else {
            existing_config = Some(sec_config);
        }
    } else if source_config.provider.is_some() {
        // No .sec, but source .env has config directives — use them
        println!("{} Using config from {}", "✓".green(), env_file);
        existing_config = Some(source_config.clone());
    } else {
        // No .sec, no source config — prompt like init
        println!("\n{}", "No .sec file found. Setting up config:".bold());
        existing_config = Some(helpers::prompt_config()?);
    }

    // Filter entries to import
    let import_entries: Vec<&dotenv::Entry> = entries
        .iter()
        .filter(|e| !skip_keys.contains(&e.key))
        .collect();

    if import_entries.is_empty() {
        println!("No new variables to import.");
        return Ok(());
    }

    // --- File-level encryption default ---
    // Priority: existing .sec config > source .env config > prompt
    let encrypt_all = if let Some(ref cfg) = existing_config {
        if let Some(val) = cfg.default_encrypt {
            let label = if val { "encrypt all" } else { "encrypt none" };
            println!("{} Using existing default: {}", "✓".green(), label);
            val
        } else {
            helpers::resolve_encrypt_default(&source_config)?
        }
    } else {
        helpers::resolve_encrypt_default(&source_config)?
    };

    // --- Per-variable configuration ---
    let num_vars = import_entries.len();
    println!(
        "\n{}",
        format!("Configuring {} variables from {}", num_vars, env_file).bold()
    );

    // Collect new directives per variable by prompting
    let import_keys: std::collections::HashSet<&str> =
        import_entries.iter().map(|e| e.key.as_str()).collect();
    let mut var_directives: Vec<Vec<dotenv::Line>> = Vec::new();
    let mut var_idx = 0;
    for entry in &entries {
        if !import_keys.contains(entry.key.as_str()) {
            continue;
        }
        let i = var_idx;
        var_idx += 1;

        println!(
            "\n{} {} = \"{}\"",
            format!("[{}/{}]", i + 1, num_vars).dimmed(),
            entry.key.bold(),
            helpers::truncate_value(&entry.value, 40).dimmed(),
        );

        let source_dirs = if entry.directives.is_empty() { None } else { Some(entry.directives.as_slice()) };
        let directives = helpers::prompt_variable_directives(&entry.key, &entry.value, encrypt_all, source_dirs)?;
        var_directives.push(directives);
    }

    if skip_keys.is_empty() {
        // Full import: build output from .env, preserve comments
        // Carry over config directives from source, replace encryption default
        let mut new_lines: Vec<dotenv::Line> = Vec::new();
        let mut var_index = 0;
        let mut inserted_config = false;

        // Build config directive lines from resolved config
        let effective_config = existing_config.as_ref().unwrap_or(&source_config);
        let config_lines = helpers::build_config_directives(effective_config, encrypt_all);

        for line in &lines {
            match line {
                // Strip source per-variable directives (we replace them with user-chosen ones)
                // But keep config directives — they're handled via config_lines
                dotenv::Line::Directive(name, _) => {
                    // Skip all directives — config ones are rebuilt, per-var ones are replaced
                    let _ = name;
                    continue;
                }

                dotenv::Line::Comment(_) | dotenv::Line::Whitespace(_) | dotenv::Line::Newline => {
                    if !inserted_config {
                        if let dotenv::Line::Comment(_) = line {
                            new_lines.extend(config_lines.clone());
                            new_lines.push(dotenv::Line::Newline);
                            new_lines.push(dotenv::Line::Newline);
                            inserted_config = true;
                        }
                    }
                    new_lines.push(line.clone());
                }

                dotenv::Line::Kv(_, _, _) => {
                    if !inserted_config {
                        new_lines.extend(config_lines.clone());
                        new_lines.push(dotenv::Line::Newline);
                        new_lines.push(dotenv::Line::Newline);
                        inserted_config = true;
                    }

                    if var_index < var_directives.len() {
                        let dirs = &var_directives[var_index];
                        if !dirs.is_empty() {
                            new_lines.extend(dirs.clone());
                            new_lines.push(dotenv::Line::Newline);
                        }
                        var_index += 1;
                    }
                    new_lines.push(line.clone());
                }
            }
        }

        if !inserted_config {
            new_lines.extend(config_lines);
            new_lines.push(dotenv::Line::Newline);
        }

        dotsec::encrypt_lines_to_sec(&new_lines, sec_file, encryption_engine).await?;
    } else {
        // New-only mode: decrypt existing .sec, append new variables
        let mut existing_lines = dotsec::decrypt_sec_to_lines(sec_file, encryption_engine).await?;

        let mut var_index = 0;
        for line in &lines {
            if let dotenv::Line::Kv(key, value, quote_type) = line {
                if !import_keys.contains(key.as_str()) {
                    continue;
                }

                if var_index < var_directives.len() {
                    let dirs = &var_directives[var_index];
                    // Ensure blank line before new entry
                    let last_is_newline = matches!(existing_lines.last(), Some(dotenv::Line::Newline));
                    if !existing_lines.is_empty() {
                        if !last_is_newline {
                            existing_lines.push(dotenv::Line::Newline);
                        }
                        existing_lines.push(dotenv::Line::Newline);
                    }
                    if !dirs.is_empty() {
                        existing_lines.extend(dirs.clone());
                        existing_lines.push(dotenv::Line::Newline);
                    }
                    var_index += 1;
                }
                existing_lines.push(dotenv::Line::Kv(key.clone(), value.clone(), quote_type.clone()));
                existing_lines.push(dotenv::Line::Newline);
            }
        }

        dotsec::encrypt_lines_to_sec(&existing_lines, sec_file, encryption_engine).await?;
    }

    println!(
        "\n{} Imported {} variables from {} into {}",
        "✓".green(),
        num_vars,
        env_file,
        sec_file
    );

    Ok(())
}

