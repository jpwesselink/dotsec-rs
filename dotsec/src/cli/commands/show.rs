use dotsec::{get_value_source, DotsecConfig, OutputFormat, RunUsing};

use clap::{arg, value_parser, Command};
use log::debug;

use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("show")
        .about("Lists sec of env file contents")
        .arg(
            arg!(<target> "sec or env")
                .value_parser(value_parser!(RunUsing))
                .default_value("sec"),
        )
        .arg(
            arg!(--"output-format" <output_format> "Output format")
                .env("DOTSEC_SHOW_OUT_OUTPUT_FORMAT")
                .value_parser(value_parser!(OutputFormat))
                .default_value("raw"),
        )
}

pub async fn match_args<'a>(
    matches: &clap::ArgMatches,
    _dotsec_config: &DotsecConfig,
    default_options: &DefaultOptions<'a>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(command_matches) = matches.subcommand_matches("show") {
        // get target
        let target_option = get_value_source(
            command_matches.value_source("target"),
            command_matches.get_one::<RunUsing>("target"),
            command_matches.get_one::<RunUsing>("target"),
            "target",
        );

        let output_format_option = get_value_source(
            command_matches.value_source("output-format"),
            command_matches.get_one::<OutputFormat>("output-format"),
            command_matches.get_one::<OutputFormat>("output-format"),
            "output-format",
        );

        let file = match target_option.unwrap() {
            RunUsing::Env => default_options.env_file.unwrap().as_str(),
            RunUsing::Sec => default_options.sec_file.unwrap().as_str(),
        };

        // let target = dotsec::ShowTarget::Sec(EncryptionEngine::Aws(AwsEncryptionOptions {
        //     key_id: Some("alias/dotsec".to_string()),
        //     secrets_manager: None,
        // }));

        let target = match target_option.unwrap() {
            RunUsing::Env => dotsec::ShowTarget::Env,
            RunUsing::Sec => {
                let encryption_engine = default_options.encryption_engine.clone();

                debug!("Encryption engine: {:?}", encryption_engine);
                dotsec::ShowTarget::Sec(encryption_engine)
            }
        };
        let output = dotsec::show(file, &target, &output_format_option.unwrap()).await?;
        println!("{}", output);
        return Ok(());
    }

    return Ok({});
}
