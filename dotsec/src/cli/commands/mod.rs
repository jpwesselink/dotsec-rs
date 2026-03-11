mod base;
mod config;
pub mod create_schema;
mod decrypt;
mod encrypt;
mod run;
pub mod show;

pub fn create_command() -> clap::Command {
    base::command()
        .subcommand(show::command())
        .subcommand(encrypt::command())
        .subcommand(decrypt::command())
        .subcommand(run::command())
        .subcommand(config::command())
        .arg_required_else_help(true)
}
