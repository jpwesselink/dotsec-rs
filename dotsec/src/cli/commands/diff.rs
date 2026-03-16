use clap::{arg, ArgAction, Command};
use colored::Colorize;
use dotenv::DiffItem;
use std::fs;
use std::time::SystemTime;

use crate::default_options::DefaultOptions;

fn format_age(modified: SystemTime) -> String {
    let Ok(elapsed) = modified.elapsed() else {
        return "just now".to_string();
    };
    let secs = elapsed.as_secs();
    if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

pub fn command() -> Command {
    Command::new("diff")
        .about("Compare .sec files — auto-selects the most recently modified as reference")
        .arg(
            arg!(--"values" "Also report value differences (off by default)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!([files] ... "Additional .sec files to compare (the default --sec-file is always included)")
                .num_args(1..),
        )
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(command_matches) = matches.subcommand_matches("diff") {
        // Start with the default sec file (from --sec-file / SEC_FILE) if it exists
        let mut files: Vec<String> = Vec::new();
        let sec_file = default_options.sec_file.to_string();
        if std::path::Path::new(&sec_file).exists() {
            files.push(sec_file);
        }

        // Add any extra files from positional args
        if let Some(extra) = command_matches.get_many::<String>("files") {
            for f in extra {
                if !files.contains(f) {
                    files.push(f.clone());
                }
            }
        }

        if files.len() < 2 {
            return Err("Need at least 2 files to compare. Pass additional .sec files as arguments.".into());
        }

        // Find the most recently modified file to use as reference
        let (ref_index, ref_modified) = files
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let modified = fs::metadata(f)
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                (i, modified)
            })
            .max_by_key(|(_, t)| *t)
            .unwrap();

        let ref_file = &files[ref_index];
        println!(
            "{} Using {} as reference (modified {})\n",
            "▶".cyan(),
            ref_file.bold(),
            format_age(ref_modified).dimmed(),
        );

        // Parse reference file
        let ref_content = dotsec::load_file(ref_file)?;
        let ref_lines = dotsec::parse_content(&ref_content)?;
        let ref_entries = dotenv::lines_to_entries(&ref_lines);

        let show_values = command_matches.get_flag("values");
        let mut has_diffs = false;

        for (i, target_file) in files.iter().enumerate() {
            if i == ref_index {
                continue;
            }

            let target_content = dotsec::load_file(target_file)?;
            let target_lines = dotsec::parse_content(&target_content)?;
            let target_entries = dotenv::lines_to_entries(&target_lines);

            let diffs: Vec<_> = dotenv::diff_entries(&ref_entries, &target_entries)
                .into_iter()
                .filter(|d| show_values || !matches!(d, DiffItem::ValueDifference { .. }))
                .collect();

            if diffs.is_empty() {
                println!("{} {} matches {}", "✓".green(), target_file, ref_file);
            } else {
                has_diffs = true;
                eprintln!(
                    "{} {} — {} difference(s) vs {}:\n",
                    "✗".red(),
                    target_file.bold(),
                    diffs.len(),
                    ref_file
                );
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
