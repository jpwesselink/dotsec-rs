use clap::Command;
use colored::Colorize;
use log::debug;

use crate::cli::helpers::{collect_validation_errors, report_validation_errors, with_progress};
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
        let lines = with_progress(
            "Decrypting...",
            dotsec::decrypt_sec_to_lines(
                sec_file,
                &default_options.encryption_engine,
                &default_options.schema_hash,
            ),
        )
        .await?;

        let entry_count = dotenv::lines_to_entries(&lines).len();
        let errors = collect_validation_errors(&lines, default_options.schema_path.as_deref())?;

        if errors.is_empty() {
            println!(
                "{} {} ({})",
                "✓".green(),
                sec_file,
                format!("{} entries", entry_count).dimmed()
            );
            if let Some(ref schema_path) = default_options.schema_path {
                println!("  {} validated against {}", "✓".green(), schema_path,);
            }
        } else if report_validation_errors(sec_file, &errors) > 0 {
            return Err("Validation failed".into());
        }
    }
    Ok(())
}
