use clap::{arg, Command};
use colored::Colorize;

use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("export")
        .about("Export dotsec.schema as JSON Schema or TypeScript")
        .arg(
            arg!(-f --format <FORMAT> "Output format")
                .required(false)
                .default_value("json-schema")
                .value_parser(["json-schema", "typescript", "ts"]),
        )
        .arg(
            arg!(-o --output <FILE> "Write to file instead of stdout")
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
                "{} No dotsec.schema found. Run `dotsec extract-schema` first or specify --schema.",
                "✗".red()
            )
        })?;

        let content = std::fs::read_to_string(schema_path)?;
        let schema = dotenv::parse_schema(&content)?;

        let format = sub.get_one::<String>("format").unwrap();
        let (output, label) = match format.as_str() {
            "typescript" | "ts" => (dotenv::schema_to_typescript(&schema), "TypeScript"),
            _ => {
                let json_schema = dotenv::schema_to_json_schema(&schema);
                (serde_json::to_string_pretty(&json_schema)?, "JSON Schema")
            }
        };

        if let Some(file) = sub.get_one::<String>("output") {
            std::fs::write(file, &output)?;
            eprintln!("{} {} written to {}", "✓".green(), label, file);
        } else {
            println!("{}", output);
        }
    }
    Ok(())
}
