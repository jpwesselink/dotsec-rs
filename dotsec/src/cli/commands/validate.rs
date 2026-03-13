use clap::Command;
use colored::Colorize;
use log::debug;

use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("validate")
        .about("Validate directives and values in .sec")
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches.subcommand_matches("validate").is_some() {
        let sec_file = default_options.sec_file;
        debug!("Decrypting {} for validation", sec_file);
        let lines = dotsec::decrypt_sec_to_lines(
            sec_file,
            &default_options.encryption_engine,
        )
        .await?;

        let entries = dotenv::lines_to_entries(&lines);
        let errors = dotenv::validate_entries_with_env(&entries);

        if errors.is_empty() {
            println!(
                "{} {} ({})",
                "✓".green(),
                sec_file,
                format!("{} entries", entries.len()).dimmed()
            );
        } else {
            eprintln!(
                "{} {} — {} error(s):\n",
                "✗".red(),
                sec_file,
                errors.len()
            );
            for error in &errors {
                eprintln!("  {} {}", "•".red(), error);
            }
            std::process::exit(1);
        }
    }
    Ok(())
}
