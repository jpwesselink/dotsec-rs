use self::commands::{create_command, diff, export, import, init, run, set, show, validate};
use crate::default_options::DefaultOptions;
use dotsec::EncryptionEngine;
use log::debug;
use std::error::Error;

pub mod commands;
pub mod helpers;

pub async fn parse_args() -> Result<(), Box<dyn Error>> {
    let command = create_command();
    let matches = command.get_matches();

    let is_init = matches.subcommand_matches("init").is_some();
    let is_import = matches.subcommand_matches("import").is_some();
    let is_run_env = matches
        .subcommand_matches("run")
        .and_then(|m| m.get_one::<String>("using"))
        .is_some_and(|v| v == "env");

    // Resolve sec file from CLI arg or default
    let default_sec = ".sec".to_string();
    let sec_file = matches
        .get_one::<String>("sec-file")
        .unwrap_or(&default_sec);

    // Read config from .sec file directives (if it exists)
    let encryption_engine = if std::path::Path::new(sec_file).exists() {
        let content = std::fs::read_to_string(sec_file)?;
        let lines = dotenv::parse_dotenv(&content)?;
        let file_config = dotenv::extract_file_config(&lines);
        debug!("file_config from {}: {:?}", sec_file, file_config);
        EncryptionEngine::from(file_config)
    } else if is_init || is_import || is_run_env {
        debug!("{} does not exist yet or not needed, using defaults", sec_file);
        EncryptionEngine::None
    } else {
        return Err(format!("{} not found. Run `dotsec init` or `dotsec import` first.", sec_file).into());
    };

    debug!("sec_file: {}, engine: {:?}", sec_file, encryption_engine);

    let default_options = DefaultOptions {
        encryption_engine,
        sec_file,
    };

    init::match_args(&matches, &default_options).await?;
    set::match_args(&matches, &default_options).await?;
    import::match_args(&matches, &default_options).await?;
    export::match_args(&matches, &default_options).await?;
    show::match_args(&matches, &default_options).await?;
    run::match_args(&matches, &default_options).await?;
    validate::match_args(&matches, &default_options).await?;
    diff::match_args(&matches, &default_options).await?;

    Ok(())
}
