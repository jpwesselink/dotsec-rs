use clap::Command;
use colored::Colorize;

use crate::cli::helpers::{strip_schema_directives, with_progress};
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("remove-directives")
        .about("Strip per-key directives from .sec (requires existing dotsec.schema)")
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches.subcommand_matches("remove-directives").is_some() {
        let sec_file = default_options.sec_file;

        // Require schema to exist
        let schema_path = dotenv::schema::discover_schema(
            sec_file,
            default_options.schema_path.as_deref(),
        );
        if schema_path.is_none() {
            eprintln!(
                "{} No dotsec.schema found. Run `dotsec eject` first to create one.",
                "✗".red()
            );
            std::process::exit(1);
        }

        // Parse the .sec file (decrypt if needed)
        let lines = with_progress(
            "Decrypting...",
            dotsec::decrypt_sec_to_lines(sec_file, &default_options.encryption_engine),
        )
        .await?;

        // Strip schema directives
        let stripped_lines = strip_schema_directives(&lines);

        // Check if anything actually changed
        if lines.len() == stripped_lines.len() {
            println!(
                "{} No per-key directives found in {}. Nothing to remove.",
                "ℹ".blue(),
                sec_file
            );
            return Ok(());
        }

        // Rewrite the .sec file
        let new_content = dotenv::lines_to_string(&stripped_lines);
        if matches!(default_options.encryption_engine, dotsec::EncryptionEngine::Aws(_)) {
            let new_lines = dotenv::parse_dotenv(&new_content)?;
            dotsec::encrypt_lines_to_sec(&new_lines, sec_file, &default_options.encryption_engine)
                .await?;
        } else {
            std::fs::write(sec_file, &new_content)?;
        }

        println!(
            "{} Removed per-key directives from {}",
            "✓".green(),
            sec_file
        );
    }
    Ok(())
}
