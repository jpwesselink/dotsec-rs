use clap::{arg, ArgAction, Command};
use colored::Colorize;
use dotenv::DiffItem;

use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("diff")
        .about("Compare env files against a base file")
        .arg(
            arg!(--"base" <FILE> "Base file (source of truth)")
                .required(true),
        )
        .arg(
            arg!(--"values" "Also report value differences (off by default)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!(<files> ... "Files to compare against the base")
                .required(true),
        )
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    _default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(command_matches) = matches.subcommand_matches("diff") {
        let base_file = command_matches.get_one::<String>("base").unwrap();
        let compare_files: Vec<String> = command_matches
            .get_many::<String>("files")
            .unwrap_or_default()
            .cloned()
            .collect();

        // Parse base
        let base_content = dotsec::load_file(base_file)?;
        let base_lines = dotsec::parse_content(&base_content)?;
        let base_entries = dotenv::lines_to_entries(&base_lines);

        let mut has_diffs = false;

        for target_file in &compare_files {
            let target_content = dotsec::load_file(target_file)?;
            let target_lines = dotsec::parse_content(&target_content)?;
            let target_entries = dotenv::lines_to_entries(&target_lines);

            let show_values = command_matches.get_flag("values");
            let diffs: Vec<_> = dotenv::diff_entries(&base_entries, &target_entries)
                .into_iter()
                .filter(|d| show_values || !matches!(d, DiffItem::ValueDifference { .. }))
                .collect();

            if diffs.is_empty() {
                println!("{} {} matches {}", "✓".green(), target_file, base_file);
            } else {
                has_diffs = true;
                eprintln!("{} {} vs {} — {} difference(s):\n", "✗".red(), base_file, target_file, diffs.len());
                for diff in &diffs {
                    let icon = match diff {
                        DiffItem::MissingKey { .. } => "-".red(),
                        DiffItem::ExtraKey { .. } => "+".yellow(),
                        DiffItem::DirectiveMismatch { .. } => "~".cyan(),
                        DiffItem::ValueDifference { .. } => "≠".magenta(),
                        DiffItem::OrderingDifference { .. } => "↕".blue(),
                    };
                    eprintln!("  {} {}", icon, diff);
                }
                eprintln!();
            }
        }

        if has_diffs {
            std::process::exit(1);
        }
    }
    Ok(())
}
