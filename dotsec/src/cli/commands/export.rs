use clap::{Arg, Command};
use colored::Colorize;

use crate::cli::helpers::with_progress;
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("export")
        .about("Decrypt .sec and write plaintext to a file or stdout")
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file (default: stdout)"),
        )
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let sub = match matches.subcommand_matches("export") {
        Some(m) => m,
        None => return Ok(()),
    };

    let sec_file = default_options.sec_file;
    let encryption_engine = &default_options.encryption_engine;

    let lines = with_progress(
        "Decrypting...",
        dotsec::decrypt_sec_to_lines(sec_file, encryption_engine),
    )
    .await?;
    // Filter out push-only entries so the exported plaintext matches what `dotsec run` would
    // inject. See `Entry::injects_into_env` (breaking change in v6.0.0).
    let env_lines = dotsec::filter_env_injectable_lines(&lines);
    let output = dotenv::lines_to_string(&env_lines);

    if let Some(out_file) = sub.get_one::<String>("output") {
        dotsec::write_sec_file(out_file, &output)?;
        eprintln!("{} Exported {} to {}", "✓".green(), sec_file, out_file);
    } else {
        print!("{}", output);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(unix)]
    fn export_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join("dotsec-test-export");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test-export.env");

        dotsec::write_sec_file(path.to_str().unwrap(), "FOO=bar\n").unwrap();

        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "exported file should be owner-only"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
