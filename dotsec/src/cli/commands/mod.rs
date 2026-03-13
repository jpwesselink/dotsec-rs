mod base;
pub mod diff;
pub mod export;
pub mod import;
pub mod init;
pub mod run;
pub mod set;
pub mod show;
pub mod validate;

pub fn create_command() -> clap::Command {
    base::command()
        .subcommand(init::command())
        .subcommand(set::command())
        .subcommand(import::command())
        .subcommand(export::command())
        .subcommand(show::command())
        .subcommand(run::command())
        .subcommand(validate::command())
        .subcommand(diff::command())
        .arg_required_else_help(true)
}
