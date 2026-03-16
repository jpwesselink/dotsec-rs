use clap::{Arg, Command};
use colored::Colorize;
use inquire::{Password, PasswordDisplayMode, Text};

use crate::cli::helpers::{self, with_progress};
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("set")
        .about("Add or update a variable in .sec")
        .arg(Arg::new("key").help("Variable name"))
        .arg(Arg::new("value").help("Variable value"))
        .arg(
            Arg::new("encrypt")
                .long("encrypt")
                .action(clap::ArgAction::SetTrue)
                .help("Mark variable for encryption"),
        )
        .arg(
            Arg::new("plaintext")
                .long("plaintext")
                .action(clap::ArgAction::SetTrue)
                .help("Mark variable as plaintext"),
        )
        .arg(
            Arg::new("type")
                .long("type")
                .value_name("TYPE")
                .help("Type directive (string, number, boolean, enum(...))"),
        )
        .arg(
            Arg::new("push")
                .long("push")
                .value_name("TARGET")
                .help("Push target (aws-ssm, aws-secrets-manager)"),
        )
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sub = match matches.subcommand_matches("set") {
        Some(m) => m,
        None => return Ok(()),
    };

    let sec_file = default_options.sec_file;
    let encryption_engine = &default_options.encryption_engine;
    let key = sub.get_one::<String>("key");
    let value = sub.get_one::<String>("value");

    let interactive = value.is_none();

    // Resolve key
    let key = match key {
        Some(k) => k.clone(),
        None => Text::new("Variable name?").prompt()?,
    };

    if key.is_empty() {
        return Err("Variable name cannot be empty".into());
    }

    // Read raw .sec lines (not decrypted) for the prompts — we may not need KMS at all
    let raw_lines = if std::path::Path::new(sec_file).exists() {
        let content = std::fs::read_to_string(sec_file)?;
        dotenv::parse_dotenv(&content)?
    } else {
        Vec::new()
    };

    // Check file-level encryption default from raw lines
    let file_default_encrypt = raw_lines.iter().any(|l| matches!(l, dotenv::Line::Directive(n, _) if n == "default-encrypt"));
    // Find existing key in raw lines (value will be an opaque ID if encrypted, but we only need position)
    let existing_pos = raw_lines.iter().position(|l| matches!(l, dotenv::Line::Kv(k, _, _) if k == &key));

    // Check if the existing variable was encrypted (has @encrypt directive or inherits from default)
    let old_was_encrypted = if let Some(kv_pos) = existing_pos {
        let dir_start = find_directive_start(&raw_lines, kv_pos);
        let has_explicit_encrypt = raw_lines[dir_start..kv_pos].iter()
            .any(|l| matches!(l, dotenv::Line::Directive(n, _) if n == "encrypt"));
        let has_explicit_plaintext = raw_lines[dir_start..kv_pos].iter()
            .any(|l| matches!(l, dotenv::Line::Directive(n, _) if n == "plaintext"));
        if has_explicit_encrypt { true }
        else if has_explicit_plaintext { false }
        else { file_default_encrypt }
    } else {
        false
    };

    // For interactive value prompt on existing plaintext vars, show current value
    let current_plaintext_value = if !old_was_encrypted {
        existing_pos.and_then(|pos| {
            if let dotenv::Line::Kv(_, v, _) = &raw_lines[pos] {
                Some(v.as_str())
            } else {
                None
            }
        })
    } else {
        None // Can't show encrypted value without KMS
    };

    // Resolve value — mask input for secret-looking keys
    let value = match value {
        Some(v) => v.clone(),
        None => {
            if helpers::looks_like_secret(&key) {
                Password::new("Value (hidden)?")
                    .with_display_mode(PasswordDisplayMode::Masked)
                    .without_confirmation()
                    .prompt()?
            } else {
                let mut prompt = Text::new("Value?");
                if let Some(current) = current_plaintext_value {
                    prompt = prompt.with_default(current);
                }
                prompt.prompt()?
            }
        }
    };

    // Build directives for this variable
    let mut new_directives: Vec<dotenv::Line> = Vec::new();
    let mut new_is_encrypted = false;

    let has_encrypt_flag = sub.get_flag("encrypt");
    let has_plaintext_flag = sub.get_flag("plaintext");
    let type_arg = sub.get_one::<String>("type");
    let push_arg = sub.get_one::<String>("push");

    if interactive {
        // Interactive: prompt for each directive
        new_directives = helpers::prompt_variable_directives(&key, &value, file_default_encrypt, None)?;

        // Determine if this variable will be encrypted
        let has_explicit_encrypt = new_directives.iter()
            .any(|l| matches!(l, dotenv::Line::Directive(n, _) if n == "encrypt"));
        let has_explicit_plaintext = new_directives.iter()
            .any(|l| matches!(l, dotenv::Line::Directive(n, _) if n == "plaintext"));
        if has_explicit_encrypt {
            new_is_encrypted = true;
        } else if has_explicit_plaintext {
            new_is_encrypted = false;
        } else {
            new_is_encrypted = file_default_encrypt;
        }
    } else {
        // Non-interactive: use flags
        if has_encrypt_flag {
            new_is_encrypted = true;
            new_directives.push(dotenv::Line::Directive("encrypt".to_string(), None));
        } else if has_plaintext_flag {
            new_directives.push(dotenv::Line::Directive("plaintext".to_string(), None));
        } else {
            // No explicit flag — inherit file default
            new_is_encrypted = file_default_encrypt;
        }

        if let Some(t) = type_arg {
            new_directives.push(dotenv::Line::Directive("type".to_string(), Some(t.clone())));
        }

        if let Some(p) = push_arg {
            new_directives.push(dotenv::Line::Directive("push".to_string(), Some(p.clone())));
        }
    }

    let needs_kms = new_is_encrypted || old_was_encrypted;

    if needs_kms {
        // Decrypt → modify → re-encrypt (full KMS round trip)
        let mut lines = with_progress("Decrypting...", dotsec::decrypt_sec_to_lines(sec_file, encryption_engine)).await?;

        let existing_pos = lines.iter().position(|l| matches!(l, dotenv::Line::Kv(k, _, _) if k == &key));
        let kv_line = dotenv::Line::Kv(key.clone(), value, dotenv::QuoteType::Double);
        let action;

        if let Some(kv_pos) = existing_pos {
            let directive_start = find_directive_start(&lines, kv_pos);
            lines.drain(directive_start..=kv_pos);

            let mut insert = new_directives;
            if !insert.is_empty() {
                insert.push(dotenv::Line::Newline);
            }
            insert.push(kv_line);
            for (i, line) in insert.into_iter().enumerate() {
                lines.insert(directive_start + i, line);
            }
            action = "Updated";
        } else {
            append_entry(&mut lines, new_directives, kv_line);
            action = "Added";
        }

        with_progress("Encrypting...", dotsec::encrypt_lines_to_sec(&lines, sec_file, encryption_engine)).await?;
        println!("{} {} {} in {}", "✓".green(), action, key.bold(), sec_file);
    } else {
        // Plaintext — modify raw .sec lines directly, no KMS needed
        let mut lines = raw_lines;
        let existing_pos = lines.iter().position(|l| matches!(l, dotenv::Line::Kv(k, _, _) if k == &key));
        let kv_line = dotenv::Line::Kv(key.clone(), value, dotenv::QuoteType::Double);
        let action;

        if let Some(kv_pos) = existing_pos {
            let directive_start = find_directive_start(&lines, kv_pos);
            lines.drain(directive_start..=kv_pos);

            let mut insert = new_directives;
            if !insert.is_empty() {
                insert.push(dotenv::Line::Newline);
            }
            insert.push(kv_line);
            for (i, line) in insert.into_iter().enumerate() {
                lines.insert(directive_start + i, line);
            }
            action = "Updated";
        } else {
            // Insert before __DOTSEC__ if it exists, otherwise append
            let dotsec_pos = find_dotsec_block_start(&lines);
            if let Some(pos) = dotsec_pos {
                // Insert before the __DOTSEC__ block
                let mut insert = vec![dotenv::Line::Newline];
                insert.extend(new_directives);
                insert.push(dotenv::Line::Newline);
                insert.push(kv_line);
                insert.push(dotenv::Line::Newline);
                for (i, line) in insert.into_iter().enumerate() {
                    lines.insert(pos + i, line);
                }
            } else {
                append_entry(&mut lines, new_directives, kv_line);
            }
            action = "Added";
        }

        let output = dotenv::lines_to_string(&lines);
        std::fs::write(sec_file, &output)?;
        println!("{} {} {} in {}", "✓".green(), action, key.bold(), sec_file);
    }

    Ok(())
}

/// Find the index where directives for a KV at `kv_pos` start.
fn find_directive_start(lines: &[dotenv::Line], kv_pos: usize) -> usize {
    let mut start = kv_pos;
    while start > 0 {
        match &lines[start - 1] {
            dotenv::Line::Directive(_, _) => start -= 1,
            dotenv::Line::Newline => {
                if start >= 2 {
                    if let dotenv::Line::Directive(_, _) = &lines[start - 2] {
                        start -= 1;
                        continue;
                    }
                }
                break;
            }
            _ => break,
        }
    }
    start
}

/// Append a new entry (directives + KV) to the end of lines.
fn append_entry(lines: &mut Vec<dotenv::Line>, directives: Vec<dotenv::Line>, kv: dotenv::Line) {
    if !lines.is_empty() {
        let last_is_newline = matches!(lines.last(), Some(dotenv::Line::Newline));
        if !last_is_newline {
            lines.push(dotenv::Line::Newline);
        }
        lines.push(dotenv::Line::Newline);
    }

    if !directives.is_empty() {
        lines.extend(directives);
        lines.push(dotenv::Line::Newline);
    }
    lines.push(kv);
    lines.push(dotenv::Line::Newline);
}

/// Find the start of the __DOTSEC__ or __DOTSEC_KEY__ block (comment + KV).
/// Returns the position of the comment or the newline before the block.
fn find_dotsec_block_start(lines: &[dotenv::Line]) -> Option<usize> {
    // Find the __DOTSEC__ or __DOTSEC_KEY__ KV
    let dotsec_kv = lines.iter().position(|l| matches!(l, dotenv::Line::Kv(k, _, _) if k == "__DOTSEC__" || k == "__DOTSEC_KEY__"))?;

    // Walk back to find the managed comment
    let mut start = dotsec_kv;
    while start > 0 {
        match &lines[start - 1] {
            dotenv::Line::Comment(c) if c.contains("do not edit the line below") => {
                start -= 1;
                // Also grab the newline before the comment
                if start > 0 && matches!(lines[start - 1], dotenv::Line::Newline) {
                    start -= 1;
                }
                break;
            }
            dotenv::Line::Newline => {
                start -= 1;
            }
            _ => break,
        }
    }
    Some(start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dotenv::{Line, QuoteType};

    // --- find_directive_start ---

    #[test]
    fn find_directive_start_no_directives() {
        let lines = vec![
            Line::Kv("FOO".into(), "bar".into(), QuoteType::Double),
        ];
        assert_eq!(find_directive_start(&lines, 0), 0);
    }

    #[test]
    fn find_directive_start_one_directive() {
        let lines = vec![
            Line::Directive("encrypt".into(), None),
            Line::Newline,
            Line::Kv("FOO".into(), "bar".into(), QuoteType::Double),
        ];
        assert_eq!(find_directive_start(&lines, 2), 0);
    }

    #[test]
    fn find_directive_start_multiple_directives() {
        let lines = vec![
            Line::Directive("encrypt".into(), None),
            Line::Directive("type".into(), Some("string".into())),
            Line::Newline,
            Line::Kv("FOO".into(), "bar".into(), QuoteType::Double),
        ];
        assert_eq!(find_directive_start(&lines, 3), 0);
    }

    #[test]
    fn find_directive_start_stops_at_comment() {
        let lines = vec![
            Line::Comment("# some comment".into()),
            Line::Newline,
            Line::Directive("encrypt".into(), None),
            Line::Newline,
            Line::Kv("FOO".into(), "bar".into(), QuoteType::Double),
        ];
        assert_eq!(find_directive_start(&lines, 4), 2);
    }

    #[test]
    fn find_directive_start_stops_at_other_kv() {
        let lines = vec![
            Line::Kv("OTHER".into(), "val".into(), QuoteType::Double),
            Line::Newline,
            Line::Newline,
            Line::Directive("encrypt".into(), None),
            Line::Newline,
            Line::Kv("FOO".into(), "bar".into(), QuoteType::Double),
        ];
        assert_eq!(find_directive_start(&lines, 5), 3);
    }

    // --- find_dotsec_block_start ---

    #[test]
    fn find_dotsec_block_no_dotsec() {
        let lines = vec![
            Line::Kv("FOO".into(), "bar".into(), QuoteType::Double),
            Line::Newline,
        ];
        assert_eq!(find_dotsec_block_start(&lines), None);
    }

    #[test]
    fn find_dotsec_block_with_comment() {
        let lines = vec![
            Line::Kv("FOO".into(), "bar".into(), QuoteType::Double),
            Line::Newline,
            Line::Newline,
            Line::Comment("# do not edit the line below, it is managed by dotsec".into()),
            Line::Newline,
            Line::Kv("__DOTSEC__".into(), "blob".into(), QuoteType::Double),
            Line::Newline,
        ];
        // Should find the newline before the comment (index 2)
        assert_eq!(find_dotsec_block_start(&lines), Some(2));
    }

    #[test]
    fn find_dotsec_block_without_comment() {
        let lines = vec![
            Line::Kv("FOO".into(), "bar".into(), QuoteType::Double),
            Line::Newline,
            Line::Newline,
            Line::Kv("__DOTSEC__".into(), "blob".into(), QuoteType::Double),
            Line::Newline,
        ];
        // Should walk back past newlines
        assert_eq!(find_dotsec_block_start(&lines), Some(1));
    }

    // --- append_entry ---

    #[test]
    fn append_entry_to_empty() {
        let mut lines: Vec<Line> = Vec::new();
        let kv = Line::Kv("FOO".into(), "bar".into(), QuoteType::Double);
        append_entry(&mut lines, vec![], kv);
        assert_eq!(lines.len(), 2); // KV + Newline
        assert!(matches!(&lines[0], Line::Kv(k, _, _) if k == "FOO"));
        assert!(matches!(&lines[1], Line::Newline));
    }

    #[test]
    fn append_entry_with_directives() {
        let mut lines: Vec<Line> = Vec::new();
        let directives = vec![
            Line::Directive("encrypt".into(), None),
            Line::Directive("type".into(), Some("string".into())),
        ];
        let kv = Line::Kv("FOO".into(), "bar".into(), QuoteType::Double);
        append_entry(&mut lines, directives, kv);
        // directives + newline + KV + newline
        assert_eq!(lines.len(), 5);
        assert!(matches!(&lines[0], Line::Directive(n, None) if n == "encrypt"));
        assert!(matches!(&lines[1], Line::Directive(n, Some(_)) if n == "type"));
        assert!(matches!(&lines[2], Line::Newline));
        assert!(matches!(&lines[3], Line::Kv(k, _, _) if k == "FOO"));
        assert!(matches!(&lines[4], Line::Newline));
    }

    #[test]
    fn append_entry_adds_blank_line_separator() {
        let mut lines = vec![
            Line::Kv("EXISTING".into(), "val".into(), QuoteType::Double),
            Line::Newline,
        ];
        let kv = Line::Kv("NEW".into(), "val".into(), QuoteType::Double);
        append_entry(&mut lines, vec![], kv);
        // existing KV + newline + blank line + new KV + newline
        assert_eq!(lines.len(), 5);
        assert!(matches!(&lines[2], Line::Newline)); // blank separator
        assert!(matches!(&lines[3], Line::Kv(k, _, _) if k == "NEW"));
    }

    #[test]
    fn append_entry_adds_newline_if_missing() {
        let mut lines = vec![
            Line::Kv("EXISTING".into(), "val".into(), QuoteType::Double),
        ];
        let kv = Line::Kv("NEW".into(), "val".into(), QuoteType::Double);
        append_entry(&mut lines, vec![], kv);
        // existing KV + added newline + blank line + new KV + newline
        assert_eq!(lines.len(), 5);
        assert!(matches!(&lines[1], Line::Newline)); // added
        assert!(matches!(&lines[2], Line::Newline)); // blank separator
    }
}
