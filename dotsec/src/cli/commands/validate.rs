use clap::Command;
use colored::Colorize;
use log::debug;

use crate::cli::helpers::with_progress;
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("validate")
        .about("Validate .sec entries against directives and schema constraints")
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches.subcommand_matches("validate").is_some() {
        let sec_file = default_options.sec_file;
        debug!("Decrypting {} for validation", sec_file);
        let lines = with_progress("Decrypting...", dotsec::decrypt_sec_to_lines(
            sec_file,
            &default_options.encryption_engine,
        )).await?;

        let entries = dotenv::lines_to_entries(&lines);
        let mut errors = dotenv::validate_entries_with_env(&entries);

        // Schema-aware validation if schema exists
        if let Some(ref schema_path) = default_options.schema_path {
            debug!("Validating against schema: {}", schema_path);
            let schema_content = std::fs::read_to_string(schema_path)?;
            let schema = dotenv::parse_schema(&schema_content)?;
            let schema_errors = dotenv::validate_entries_against_schema(&entries, &schema);
            errors.extend(schema_errors);
        }

        let error_count = errors.iter().filter(|e| e.severity == dotenv::Severity::Error).count();
        let warning_count = errors.iter().filter(|e| e.severity == dotenv::Severity::Warning).count();

        if errors.is_empty() {
            println!(
                "{} {} ({})",
                "✓".green(),
                sec_file,
                format!("{} entries", entries.len()).dimmed()
            );
            if let Some(ref schema_path) = default_options.schema_path {
                println!(
                    "  {} validated against {}",
                    "✓".green(),
                    schema_path,
                );
            }
        } else {
            // Print errors first, then warnings
            if error_count > 0 {
                eprintln!(
                    "{} {} — {} error(s):\n",
                    "✗".red(),
                    sec_file,
                    error_count
                );
                for error in errors.iter().filter(|e| e.severity == dotenv::Severity::Error) {
                    eprintln!("  {} {}", "•".red(), error);
                }
            }
            if warning_count > 0 {
                if error_count > 0 { eprintln!(); }
                eprintln!(
                    "{} {} warning(s):\n",
                    "⚠".yellow(),
                    warning_count
                );
                for warning in errors.iter().filter(|e| e.severity == dotenv::Severity::Warning) {
                    eprintln!("  {} {}", "•".yellow(), warning);
                }
            }
            if error_count > 0 {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
