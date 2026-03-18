mod codegen;
mod export;

use clap::Command;
use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("schema")
        .about("Export or generate code from dotsec.schema")
        .subcommand_required(true)
        .subcommand(export::command())
        .subcommand(codegen::command())
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(sub) = matches.subcommand_matches("schema") {
        export::match_args(sub, default_options).await?;
        codegen::match_args(sub, default_options).await?;
    }
    Ok(())
}
