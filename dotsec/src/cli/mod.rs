use self::commands::{
    create_command, diff, eject, encrypt, export, format, header, import, init, migrate, push,
    remove_directives, rotate_key, run, schema, set, show, validate,
};
use crate::default_options::DefaultOptions;
use dotsec::EncryptionEngine;
use log::debug;
use std::error::Error;

pub mod commands;
pub mod helpers;
mod poster;

pub async fn parse_args() -> Result<(), Box<dyn Error>> {
    let command = create_command();
    let matches = command.get_matches();

    // No subcommand — render the brand poster (logo, quick start, license).
    if matches.subcommand_name().is_none() {
        poster::show().await;
        return Ok(());
    }

    let is_init = matches.subcommand_matches("init").is_some();
    let is_import = matches.subcommand_matches("import").is_some();
    let is_migrate = matches.subcommand_matches("migrate").is_some();
    let is_diff = matches.subcommand_matches("diff").is_some();
    let is_eject = matches.subcommand_matches("extract-schema").is_some();
    let is_schema = matches.subcommand_matches("schema").is_some();
    let is_set = matches.subcommand_matches("set").is_some();
    let is_run_env = matches
        .subcommand_matches("run")
        .is_some_and(|m| m.contains_id("env-file") && m.get_one::<String>("env-file").is_some());

    // Resolve sec file from CLI arg or default
    let default_sec = ".sec".to_string();
    let sec_file = matches
        .get_one::<String>("sec-file")
        .unwrap_or(&default_sec);

    // Resolve schema path from CLI arg or discovery
    let explicit_schema = matches.get_one::<String>("schema").map(|s| s.as_str());
    let schema_path = dotenv::schema::discover_schema(sec_file, explicit_schema)?;
    debug!("schema_path: {:?}", schema_path);

    // Hash the schema's *canonical* form for v3 file-MAC binding. We canonicalize
    // before hashing so cosmetic edits (adding `@description`, reordering
    // directives within an entry, reformatting whitespace) leave teammates'
    // MACs valid. Only semantic changes — `@type`, `@encrypt`, `@push`,
    // validation constraints, key add/remove — invalidate them.
    // Missing schema ⇒ hash of empty bytes, a stable sentinel.
    let schema_hash = match &schema_path {
        Some(path) => {
            let content = std::fs::read_to_string(path)?;
            let schema = dotenv::parse_schema(&content)?;
            crypto::mac::schema_hash(Some(&dotenv::schema_to_canonical_bytes(&schema)))
        }
        None => crypto::mac::schema_hash(None),
    };

    // Read config from .sec file directives (if it exists)
    let encryption_engine = if std::path::Path::new(sec_file).exists() {
        let content = std::fs::read_to_string(sec_file)?;
        let lines = dotenv::parse_dotenv(&content)?;
        let file_config = dotenv::extract_file_config(&lines);
        debug!("file_config from {}: {:?}", sec_file, file_config);
        EncryptionEngine::try_from(file_config)?
    } else if is_init
        || is_import
        || is_migrate
        || is_diff
        || is_eject
        || is_schema
        || is_run_env
        || is_set
    {
        debug!(
            "{} does not exist yet or not needed, using defaults",
            sec_file
        );
        EncryptionEngine::None
    } else {
        return Err(format!("{} not found. Run `dotsec set KEY value` to create one, or `dotsec import` to migrate from .env.", sec_file).into());
    };

    debug!("sec_file: {}, engine: {:?}", sec_file, encryption_engine);

    let default_options = DefaultOptions {
        encryption_engine,
        sec_file,
        schema_path,
        schema_hash,
    };

    init::match_args(&matches, &default_options).await?;
    set::match_args(&matches, &default_options).await?;
    encrypt::match_args(&matches, &default_options).await?;
    import::match_args(&matches, &default_options).await?;
    export::match_args(&matches, &default_options).await?;
    show::match_args(&matches, &default_options).await?;
    run::match_args(&matches, &default_options).await?;
    validate::match_args(&matches, &default_options).await?;
    diff::match_args(&matches, &default_options).await?;
    rotate_key::match_args(&matches, &default_options).await?;
    migrate::match_args(&matches, &default_options).await?;
    push::match_args(&matches, &default_options).await?;
    eject::match_args(&matches, &default_options).await?;
    format::match_args(&matches, &default_options).await?;
    header::match_args(&matches, &default_options).await?;
    remove_directives::match_args(&matches, &default_options).await?;
    schema::match_args(&matches, &default_options).await?;

    Ok(())
}
