use clap::Command;
use colored::Colorize;
use log::debug;

use crate::cli::helpers::with_progress;
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("format")
        .about("Reorder .sec entries to match schema key ordering")
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches.subcommand_matches("format").is_some() {
        let sec_file = default_options.sec_file;

        let schema_path = default_options.schema_path.as_ref().ok_or_else(|| {
            format!(
                "{} No dotsec.schema found. Format requires a schema to define key ordering.",
                "✗".red()
            )
        })?;

        debug!("Formatting {} against schema {}", sec_file, schema_path);

        let schema_content = std::fs::read_to_string(schema_path)?;
        let schema = dotenv::parse_schema(&schema_content)?;

        let lines = with_progress(
            "Decrypting...",
            dotsec::decrypt_sec_to_lines(sec_file, &default_options.encryption_engine),
        )
        .await?;

        // Validate entries against schema and warn (non-blocking)
        let entries = dotenv::lines_to_entries(&lines);
        let validation_errors = dotenv::validate_entries_against_schema(&entries, &schema);
        if !validation_errors.is_empty() {
            let warning_count = validation_errors.len();
            eprintln!(
                "{} {} schema validation warning(s):",
                "⚠".yellow(),
                warning_count
            );
            for err in &validation_errors {
                eprintln!("  {} {}", "•".yellow(), err);
            }
            eprintln!();
        }

        let formatted = dotenv::format_lines_by_schema(&lines, &schema);

        // Check if anything changed
        let old_content = dotenv::lines_to_string(&lines);
        let new_content = dotenv::lines_to_string(&formatted);

        if old_content == new_content {
            println!(
                "{} {} is already in schema order",
                "✓".green(),
                sec_file
            );
            return Ok(());
        }

        // Write back
        if matches!(default_options.encryption_engine, dotsec::EncryptionEngine::Aws(_)) {
            let new_lines = dotenv::parse_dotenv(&new_content)?;
            dotsec::encrypt_lines_to_sec(&new_lines, sec_file, &default_options.encryption_engine)
                .await?;
        } else {
            std::fs::write(sec_file, &new_content)?;
        }

        println!(
            "{} Formatted {} to match schema ordering",
            "✓".green(),
            sec_file
        );
    }
    Ok(())
}
