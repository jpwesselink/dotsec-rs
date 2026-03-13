use dotsec::OutputFormat;

use clap::{arg, value_parser, Command};
use log::debug;

use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("show")
        .about("Show decrypted .sec file contents")
        .arg(
            arg!(--"output-format" <output_format> "Output format")
                .env("DOTSEC_SHOW_OUTPUT_FORMAT")
                .value_parser(value_parser!(OutputFormat))
                .default_value("raw"),
        )
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(command_matches) = matches.subcommand_matches("show") {
        let output_format = command_matches
            .get_one::<OutputFormat>("output-format")
            .unwrap_or(&OutputFormat::Raw);

        let sec_file = default_options.sec_file;
        debug!("Showing decrypted {}", sec_file);

        let output = dotsec::show(sec_file, &default_options.encryption_engine, output_format).await?;
        println!("{}", output);
    }
    Ok(())
}
