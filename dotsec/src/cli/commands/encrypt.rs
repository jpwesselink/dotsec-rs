use clap::Command;
use colored::Colorize;

use crate::cli::helpers::with_progress;
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("encrypt").about(
        "Re-encrypt the .sec file and refresh its MAC (use after editing directives or schema)",
    )
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches.subcommand_matches("encrypt").is_none() {
        return Ok(());
    }

    let sec_file = default_options.sec_file;
    let encryption_engine = &default_options.encryption_engine;

    if !std::path::Path::new(sec_file).exists() {
        return Err(format!("{} not found", sec_file).into());
    }

    // Read the file's intent without verifying the file MAC. That MAC is what
    // we're about to recompute, so verifying it first would defeat the purpose
    // of the command — the user runs `dotsec encrypt` precisely when the MAC
    // has gone stale due to legitimate directive edits.
    //
    // Per-value AEAD still authenticates every ENC[...] value during decrypt;
    // we're only bypassing the *file-level* MAC, not the per-value integrity.
    let lines = with_progress(
        "Decrypting (bypassing file MAC)...",
        dotsec::decrypt_sec_to_lines_for_remac_only(sec_file, encryption_engine),
    )
    .await?;

    // Reload the schema so its directives merge into the encrypt pass.
    // (default_options.schema_hash is already derived from the same schema.)
    let schema = if let Some(path) = &default_options.schema_path {
        let content = std::fs::read_to_string(path)?;
        Some(dotenv::parse_schema(&content)?)
    } else {
        None
    };

    with_progress(
        "Re-encrypting...",
        dotsec::encrypt_lines_to_sec(
            &lines,
            sec_file,
            encryption_engine,
            schema.as_ref(),
        ),
    )
    .await?;

    println!(
        "{} Re-encrypted {} and refreshed file MAC",
        "✓".green(),
        sec_file.bold()
    );
    Ok(())
}
