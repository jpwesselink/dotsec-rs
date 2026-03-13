use clap::{arg, Command};
use log::debug;

use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("run")
        .about("Run a command with decrypted env vars injected from .sec")
        .arg(arg!(<cmd> ... "Command to run").trailing_var_arg(true))
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(command_matches) = matches.subcommand_matches("run") {
        let cmd_parts: Vec<String> = command_matches
            .get_many::<String>("cmd")
            .unwrap_or_default()
            .cloned()
            .collect();

        if cmd_parts.is_empty() {
            return Err("No command specified".into());
        }

        let encryption_engine = &default_options.encryption_engine;
        debug!("Decrypting {} for run", default_options.sec_file);
        let lines =
            dotsec::decrypt_sec_to_lines(default_options.sec_file, encryption_engine).await?;
        let env_vars = dotsec::resolve_env_vars(&lines);
        let secrets = dotsec::collect_secret_values(&lines, &env_vars);
        debug!(
            "Running: {:?} with {} env vars, {} secrets redacted",
            cmd_parts,
            env_vars.len(),
            secrets.len()
        );

        let status = dotsec::run_command(&cmd_parts, &env_vars, &secrets).await?;
        std::process::exit(status);
    }
    Ok(())
}
