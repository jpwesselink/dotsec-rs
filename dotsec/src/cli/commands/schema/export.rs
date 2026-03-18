use clap::{arg, Command};
use colored::Colorize;

use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("export")
        .about("Export dotsec.schema as JSON Schema")
        .arg(
            arg!(-o --output <FILE> "Write JSON Schema to file instead of stdout")
                .required(false),
        )
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(sub) = matches.subcommand_matches("export") {
        let schema_path = default_options.schema_path.as_ref().ok_or_else(|| {
            format!(
                "{} No dotsec.schema found. Run `dotsec eject` first or specify --schema.",
                "✗".red()
            )
        })?;

        let content = std::fs::read_to_string(schema_path)?;
        let schema = dotenv::parse_schema(&content)?;
        let json_schema = dotenv::schema_to_json_schema(&schema);
        let output = serde_json::to_string_pretty(&json_schema)?;

        if let Some(file) = sub.get_one::<String>("output") {
            std::fs::write(file, &output)?;
            eprintln!("{} JSON Schema written to {}", "✓".green(), file);
        } else {
            println!("{}", output);
        }
    }
    Ok(())
}
