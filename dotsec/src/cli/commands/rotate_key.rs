use clap::{Arg, ArgAction, Command};
use colored::Colorize;

use crate::cli::helpers::with_progress;
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("rotate-key")
        .about("Generate a new DEK and re-encrypt all values")
        .arg(
            Arg::new("new-keypair")
                .long("new-keypair")
                .action(ArgAction::SetTrue)
                .help(
                    "Also replace the age keypair (local provider). Use this when \
                     .sec.key or DOTSEC_PRIVATE_KEY may have leaked: rotating only \
                     the DEK keeps it wrapped to the old key.",
                ),
        )
        .after_help(
            "Examples:\n  \
             dotsec rotate-key                  # new DEK, same key (routine rotation)\n  \
             dotsec rotate-key --new-keypair    # new DEK and new age keypair (key leaked)",
        )
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(sub) = matches.subcommand_matches("rotate-key") else {
        return Ok(());
    };
    let new_keypair = sub.get_flag("new-keypair");

    let sec_file = default_options.sec_file;
    let encryption_engine = &default_options.encryption_engine;

    // Decrypt all values with the old DEK
    let lines = with_progress(
        "Decrypting with old key...",
        dotsec::decrypt_sec_to_lines(sec_file, encryption_engine, &default_options.schema_hash),
    )
    .await?;

    // With --new-keypair (local only): the new identity and where it goes.
    // Written to `<key file>.new` first and renamed into place only after the
    // .sec is rewritten, so a crash never leaves a .sec whose key is lost.
    let mut new_key_path: Option<String> = None;

    // Generate a new DEK and wrap it with the appropriate provider
    let (new_dek, new_wrapped_dek) = match encryption_engine {
        dotsec::EncryptionEngine::Aws(_) if new_keypair => {
            return Err(
                "--new-keypair only applies to the local provider. With AWS KMS there is \
                        no key on disk: revoke the leaked principal's kms:Decrypt in IAM (and \
                        consider rotating the KMS key), then run `dotsec rotate-key`."
                    .into(),
            );
        }
        dotsec::EncryptionEngine::Local(opts) if new_keypair => {
            let key_path = opts
                .key_file
                .clone()
                .unwrap_or_else(|| format!("{}.key", sec_file));
            let (identity, recipient) = crypto::local::generate_keypair();
            let identity = zeroize::Zeroizing::new(identity);
            dotsec::write_sec_file(&format!("{key_path}.new"), &format!("{}\n", *identity))?;
            let dek = crypto::generate_dek();
            let wrapped = crypto::local::wrap_dek(&dek, &recipient)?;
            new_key_path = Some(key_path);
            (dek, wrapped)
        }
        dotsec::EncryptionEngine::Aws(opts) => {
            let key_id = opts.key_id.as_deref().ok_or("AWS key_id is required")?;
            aws::generate_data_key(
                key_id,
                opts.region.as_deref(),
                &dotsec::kms_encryption_context(),
            )
            .await?
        }
        dotsec::EncryptionEngine::Local(opts) => {
            let private_key = crypto::local::load_private_key(sec_file, opts.key_file.as_deref())?;
            let recipient = crypto::local::recipient_from_identity(&private_key)?;
            let dek = crypto::generate_dek();
            let wrapped = crypto::local::wrap_dek(&dek, &recipient)?;
            (dek, wrapped)
        }
        dotsec::EncryptionEngine::None => return Err("Encryption engine is required".into()),
    };

    // Load + merge schema directives onto entries — without this, a value
    // encrypted via schema-only `@encrypt` would be treated as plaintext and
    // rotated as raw plaintext under the new DEK, with a MAC that vouches for
    // the leak. The merge gives schema-only @encrypt entries the same
    // treatment as inline-@encrypt entries.
    let schema = if let Some(path) = &default_options.schema_path {
        let content = std::fs::read_to_string(path)?;
        Some(dotenv::parse_schema(&content)?)
    } else {
        None
    };
    let entries = dotsec::entries_with_schema(&lines, schema.as_ref());

    // Re-encrypt every @encrypt entry (now including schema-merged ones)
    // under the new DEK.
    let mut sec_lines: Vec<dotenv::Line> = Vec::new();
    for line in &lines {
        match line {
            dotenv::Line::Kv {
                key,
                value,
                quote_type,
            } => {
                let entry = entries.iter().find(|e| e.key == *key);
                let should_encrypt = entry.is_some_and(|e| e.has_directive("encrypt"));
                if should_encrypt {
                    let encrypted = crypto::encrypt_value(value, &new_dek, key)?;
                    sec_lines.push(dotenv::Line::Kv {
                        key: key.clone(),
                        value: encrypted,
                        quote_type: quote_type.clone(),
                    });
                } else {
                    sec_lines.push(line.clone());
                }
            }
            other => sec_lines.push(other.clone()),
        }
    }

    // Build v3 header: MAC over the final canonical bytes under the new DEK,
    // bound to the same schema hash the encrypt path would derive.
    let schema_hash = match schema.as_ref() {
        Some(s) => crypto::mac::schema_hash(Some(&dotenv::schema_to_canonical_bytes(s))),
        None => crypto::mac::empty_schema_hash(),
    };
    let mac = dotsec::compute_v3_mac(&sec_lines, &new_dek, &schema_hash);
    let header = dotsec::header_v3::HeaderV3 {
        mac,
        wrapped_dek: new_wrapped_dek.to_vec(),
    };
    dotsec::insert_v3_header(&mut sec_lines, header);

    // new_dek auto-zeroizes when dropped here.

    let output = dotenv::lines_to_string(&sec_lines);
    dotsec::write_sec_file(sec_file, &output)?;

    if let Some(key_path) = new_key_path {
        let staged = format!("{key_path}.new");
        std::fs::rename(&staged, &key_path).map_err(|e| {
            format!(
                "{sec_file} is now encrypted to the NEW key, which is in {staged}, but moving it \
                 to {key_path} failed: {e}. Move it there yourself — the old key no longer works."
            )
        })?;
        println!(
            "\n{} Keypair replaced — {} re-encrypted with a new DEK wrapped to a new age key",
            "✓".green(),
            sec_file.bold()
        );
        println!("  New private key: {}", key_path.bold());
        if std::env::var("DOTSEC_PRIVATE_KEY").is_ok() {
            println!(
                "  {} DOTSEC_PRIVATE_KEY is set and still holds the OLD key (it wins over the key \
                 file). Update it — and every CI secret / password-manager entry — with the \
                 contents of {}.",
                "!".yellow().bold(),
                key_path
            );
        }
        println!(
            "  Share the new key with your team over a secure channel. The old key can no \
             longer decrypt the current {}, but it still decrypts every older version in \
             git history — treat those secrets as exposed and rotate them at the source.",
            sec_file
        );
    } else {
        println!(
            "\n{} Key rotated — all values in {} re-encrypted with new DEK",
            "✓".green(),
            sec_file.bold()
        );
    }

    Ok(())
}
