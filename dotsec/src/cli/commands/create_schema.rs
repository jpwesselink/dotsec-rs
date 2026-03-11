use dotsec::{create_configuration_json_schema, DotsecConfig};
use log::debug;
use schemars::schema_for;

use crate::default_options::DefaultOptions;
#[allow(dead_code)]
pub fn run() {
    debug!("Creating schema...");

    let schema = schema_for!(DotsecConfig);
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
}

pub async fn match_args<'a>(
    matches: &clap::ArgMatches,
    _dotsec_config: &DotsecConfig,
    _default_options: &DefaultOptions<'a>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(config_command_matches) = matches.subcommand_matches("config") {
        if let Some(config_create_matches) = config_command_matches.subcommand_matches("create") {
            if let Some(_) = config_create_matches.subcommand_matches("jsonschema") {
                let json_schema = create_configuration_json_schema()?;
                println!("{}", json_schema);
            }
        }
        // get target
        // let target_option = get_value_source(
        //     config_command_matches.value_source("target"),
        //     config_command_matches.get_one::<RunUsing>("target"),
        //     config_command_matches.get_one::<RunUsing>("target"),
        //     "target",
        // );

        // let output_format_option = get_value_source(
        //     config_command_matches.value_source("output-format"),
        //     config_command_matches.get_one::<OutputFormat>("output-format"),
        //     config_command_matches.get_one::<OutputFormat>("output-format"),
        //     "output-format",
        // );

        // let file = match target_option.unwrap() {
        //     RunUsing::Env => default_options.env_file.unwrap().as_str(),
        //     RunUsing::Sec => default_options.sec_file.unwrap().as_str(),
        // };

        // // let target = dotsec::ShowTarget::Sec(EncryptionEngine::Aws(AwsEncryptionOptions {
        // //     key_id: Some("alias/dotsec".to_string()),
        // //     secrets_manager: None,
        // // }));

        // let target = match target_option.unwrap() {
        //     RunUsing::Env => dotsec::ShowTarget::Env,
        //     RunUsing::Sec => {
        //         let encryption_engine = default_options.encryption_engine.clone();

        //         dotsec::ShowTarget::Sec(encryption_engine)
        //     }
        // };
        // dotsec::show(file, &target, &output_format_option.unwrap()).await?;

        return Ok(());
    }

    return Ok({});
}
