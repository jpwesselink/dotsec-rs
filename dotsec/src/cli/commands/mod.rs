mod base;
pub mod diff;
pub mod eject;
pub mod export;
pub mod format;
pub mod import;
pub mod init;
pub mod migrate;
pub mod push;
pub mod remove_directives;
pub mod rotate_key;
pub mod schema;
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
        .subcommand(rotate_key::command())
        .subcommand(migrate::command())
        .subcommand(push::command())
        .subcommand(eject::command())
        .subcommand(format::command())
        .subcommand(remove_directives::command())
        .subcommand(schema::command())
        .arg_required_else_help(false)
}
