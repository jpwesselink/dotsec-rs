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

    let lines = with_progress("Decrypting...", dotsec::decrypt_sec_to_lines(sec_file, encryption_engine)).await?;
    let output = dotenv::lines_to_string(&lines);

    if let Some(out_file) = sub.get_one::<String>("output") {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true).create(true).truncate(true)
                .mode(0o600)
                .open(out_file)?
                .write_all(output.as_bytes())?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(out_file, &output)?;
        }
        eprintln!(
            "{} Exported {} to {}",
            "✓".green(),
            sec_file,
            out_file
        );
    } else {
        print!("{}", output);
    }

    Ok(())
}
