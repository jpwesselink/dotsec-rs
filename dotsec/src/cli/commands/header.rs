use clap::Command;
use colored::Colorize;

use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("header").about("Add or update the dotsec header in a .sec file")
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches.subcommand_matches("header").is_none() {
        return Ok(());
    }

    let sec_file = default_options.sec_file;

    if !std::path::Path::new(sec_file).exists() {
        return Err(format!("{} not found", sec_file).into());
    }

    let content = std::fs::read_to_string(sec_file)?;
    let mut lines = dotenv::parse_dotenv(&content)?;

    if dotsec::has_header(&lines) {
        // Remove existing header lines (comments matching "# dotsec v" and the URL line + their newlines)
        let mut i = 0;
        while i < lines.len() {
            match &lines[i] {
                dotenv::Line::Comment { text } if text.starts_with("# dotsec v") => {
                    lines.remove(i);
                    // Remove trailing newline
                    if i < lines.len() && matches!(lines[i], dotenv::Line::Newline) {
                        lines.remove(i);
                    }
                }
                dotenv::Line::Comment { text }
                    if text.contains("github.com/jpwesselink/dotsec-rs") =>
                {
                    lines.remove(i);
                    // Remove trailing newline
                    if i < lines.len() && matches!(lines[i], dotenv::Line::Newline) {
                        lines.remove(i);
                    }
                }
                _ => i += 1,
            }
        }
    }

    // Prepend fresh header
    let mut new_lines = dotsec::generate_header();
    new_lines.push(dotenv::Line::Newline);
    new_lines.extend(lines);

    let output = dotenv::lines_to_string(&new_lines);
    dotsec::write_sec_file(sec_file, &output)?;

    eprintln!("{} Updated header in {}", "✓".green(), sec_file);

    Ok(())
}
