use clap::Command;
use colored::Colorize;

use crate::cli::helpers;
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("init")
        .about("Initialize an empty .sec file with encryption config")
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches.subcommand_matches("init").is_none() {
        return Ok(());
    }

    let sec_file = default_options.sec_file;

    if std::path::Path::new(sec_file).exists() {
        println!("{} {} already exists, skipping.", "✓".green(), sec_file);
        return Ok(());
    }

    println!("\n{}", "Creating .sec file".bold());

    let config = helpers::prompt_config()?;
    let encrypt_all = helpers::resolve_encrypt_default(&config)?;
    let mut lines = helpers::build_config_directives(&config, encrypt_all);
    lines.push(dotenv::Line::Newline);

    let output = dotenv::lines_to_string(&lines);
    std::fs::write(sec_file, &output)?;
    println!("{} Created {}", "✓".green(), sec_file);
    println!(
        "\n{} Run {} to add variables.",
        "→".bold(),
        "dotsec set".cyan()
    );

    Ok(())
}
