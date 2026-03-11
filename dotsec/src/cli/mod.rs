use self::commands::{create_command, create_schema, show};
use miette::Result;
use thiserror::Error;

use crate::default_options::DefaultOptions;
use colored::Colorize;
use dotsec::{get_value_source, DotsecConfig, EncryptionEngine, Platform};
use log::{debug, trace};
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

pub mod commands;

fn read_dotsec_config_from_file<P: AsRef<Path>>(path: P) -> Result<DotsecConfig, Box<dyn Error>> {
    // Open the file in read-only mode with buffer.
    // create a slice of the path
    let path_slice1 = path.as_ref();
    let path_slice2 = path.as_ref();
    let file = File::open(path_slice2)?;
    debug!(
        "Reading {} config from {}",
        "dotsec config".yellow(),
        path_slice1.display().to_string().cyan()
    );
    let reader: BufReader<File> = BufReader::new(file);

    trace!("reader: {:?}", reader);
    // Read the JSON contents of the file as an instance of `DotsecConfig`.
    let u: DotsecConfig = serde_json::from_reader(reader)?;
    debug!("u: {:?}", u);
    // Return the `DotsecConfig`.
    Ok(u)
}

// tokio
pub async fn parse_args() -> Result<(), Box<dyn Error>> {
    // Order of precedence:
    // Command line.
    // Config file thats name is declared on the command line.
    // Environment vars
    // Local config file (if exists)
    // Global config file (if exists)

    // we are are looking for the config file first on the command line
    let command = create_command();
    // get matches
    let matches = command.get_matches();
    // match subcommand config > create > jsonschema
    let default_config_path = PathBuf::from("dotsec.json");
    // if there's no match, just default it to dotsec.json

    let config_path = matches
        .get_one::<PathBuf>("config")
        .unwrap_or(&default_config_path);

    debug!("config_path: {:?}", config_path);

    // load it with tokio
    let dotsec_config = read_dotsec_config_from_file(config_path).map_err(|e| {
        // return a new error with the message
        let message = format!(
            "reading the dotsec config file {}: {}",
            config_path.display().to_string(),
            e.to_string()
        );
        Box::new(std::io::Error::new(std::io::ErrorKind::Other, message))
    })?;
    debug!("dotsec_config: {:?}", dotsec_config);
    let platforms = dotsec_config.clone().platforms.unwrap_or_default();

    debug!("platforms: {:?}", platforms);
    let command_defaults = dotsec_config.clone().command_defaults.unwrap_or_default();
    debug!("command_defaults: {:?}", command_defaults);
    let platform = command_defaults.platform.unwrap_or_default();
    debug!("platform: {:?}", platform);
    let encryption_engine = match platform {
        Platform::Aws => Ok(EncryptionEngine::Aws(platforms.aws.unwrap_or_default())),
        Platform::Pki => Ok(EncryptionEngine::Pki(platforms.pki.unwrap_or_default())),
        Platform::None => Err("Platform is required"),
    }?;
    // let commands: Commands = command_defaults.commands.unwrap_or(Commands::default());

    // let run_command = commands.run.unwrap_or(Run {
    //     no_redaction: None,
    //     using: None,
    // });

    // let encryption_engine = command_defaults
    //     .encryption_engine
    //     .unwrap_or(EncryptionEngine::Aws(AwsEncryptionOptions {
    //         key_id: None,
    //         secrets_manager: None,
    //     }));

    let config_env_file_option = command_defaults.env_file.as_ref();

    let config_sec_file_option = command_defaults.sec_file.as_ref();
    // let no_redaction = run_command.no_redaction;

    // // redaction
    // let redaction = dotsec_config
    //     .clone()
    //     .redaction
    //     .unwrap_or(Redaction {
    //         exclude: [].to_vec(),
    //     })
    //     .clone();

    // get the value for env-file

    let env_file = get_value_source(
        matches.value_source("env-file"),
        matches.get_one::<String>("env-file"),
        config_env_file_option,
        "env-file",
    );

    let sec_file = get_value_source(
        matches.value_source("sec-file"),
        matches.get_one::<String>("sec-file"),
        config_sec_file_option,
        "sec-file",
    );

    let default_options: DefaultOptions = DefaultOptions {
        encryption_engine,
        env_file,
        sec_file,
    };

    debug!("default_options: {:?}", default_options);
    // show
    show::match_args(&matches, &dotsec_config, &default_options).await?;
    create_schema::match_args(&matches, &dotsec_config, &default_options).await?;
    Ok(())
    // if default_options.env_file.is_some() {
    //     let env_file = default_options.env_file.unwrap();
    //     println!("env_file: {:?}", env_file);
    //     println!("env_file: {:?}", env_file);
    //     println!("env_file: {:?}", env_file);
    // }
    // // run
    // if let Some(matches) = matches.subcommand_matches("run") {
    //     // get redaction option

    //     let no_redaction = get_value_source(
    //         matches.value_source("no-redaction"),
    //         matches.get_one::<bool>("no-redaction"),
    //         run_command.no_redaction.as_ref(),
    //         "no-redaction",
    //     );

    //     let no_redaction = no_redaction.unwrap_or(&false);

    //     info!("no_redaction: {:?}", no_redaction);

    //     trace!("env_file: {:?}", env_file);
    //     let env_contents_option: Result<String, std::io::Error> =
    //         load_file(&env_file.unwrap()).await;

    //     let env_contents = match env_contents_option {
    //         Ok(contents) => contents,
    //         Err(e) => {
    //             eprintln!("Error: {}", e);
    //             process::exit(1);
    //         }
    //     };

    //     trace!("env_contents: {:?}", env_contents);

    //     run();
    // }
    // if let Some(config_matches) = matches.subcommand_matches("config") {
    //     if let Some(create_matches) = config_matches.subcommand_matches("create") {
    //         if let Some(_meh) = create_matches.subcommand_matches("jsonschema") {
    //             create_schema();
    //         }
    //     }
    // }
}
