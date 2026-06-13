use clap::Command;
use colored::Colorize;

use crate::cli::helpers::with_progress;
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("rotate-key").about("Generate a new DEK and re-encrypt all values")
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches.subcommand_matches("rotate-key").is_none() {
        return Ok(());
    }

    let sec_file = default_options.sec_file;
    let encryption_engine = &default_options.encryption_engine;

    // Decrypt all values with the old DEK
    let lines = with_progress(
        "Decrypting with old key...",
        dotsec::decrypt_sec_to_lines(sec_file, encryption_engine, &default_options.schema_hash),
    )
    .await?;

    // Generate a new DEK and wrap it with the appropriate provider
    let (new_dek, new_wrapped_dek) = match encryption_engine {
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
    let mut entries = dotenv::lines_to_entries(&lines);
    dotsec::merge_schema_directives_into_entries(&mut entries, schema.as_ref());

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

    println!(
        "\n{} Key rotated — all values in {} re-encrypted with new DEK",
        "✓".green(),
        sec_file.bold()
    );

    Ok(())
}
