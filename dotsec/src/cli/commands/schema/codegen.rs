use clap::{arg, Command};
use colored::Colorize;

use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("codegen")
        .about("Generate typed code from dotsec.schema")
        .arg(
            arg!(-l --lang <LANG> "Target language")
                .required(false)
                .default_value("typescript"),
        )
        .arg(
            arg!(-o --output <FILE> "Write generated code to file instead of stdout")
                .required(false),
        )
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(sub) = matches.subcommand_matches("codegen") {
        let lang = sub.get_one::<String>("lang").unwrap();

        let schema_path = default_options.schema_path.as_ref().ok_or_else(|| {
            format!(
                "{} No dotsec.schema found. Run `dotsec eject` first or specify --schema.",
                "✗".red()
            )
        })?;

        let content = std::fs::read_to_string(schema_path)?;
        let schema = dotenv::parse_schema(&content)?;

        let output = match lang.as_str() {
            "typescript" | "ts" => dotenv::schema_to_typescript(&schema),
            _ => {
                return Err(format!("Unsupported language: {}. Supported: typescript", lang).into());
            }
        };

        if let Some(file) = sub.get_one::<String>("output") {
            std::fs::write(file, &output)?;
            eprintln!("{} {} code written to {}", "✓".green(), lang, file);
        } else {
            println!("{}", output);
        }
    }
    Ok(())
}
