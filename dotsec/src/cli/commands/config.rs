use clap::Command;

pub fn command() -> Command {
    Command::new("config")
        .about("Configuration")
        .subcommand(Command::new("validate").about("Validates a dotsec config file"))
        .subcommand(
            Command::new("create")
                .subcommand(
                    Command::new("jsonschema")
                        .about("Creates a JSON schema for validating dotsec.json files"),
                )
                .arg_required_else_help(true),
        )
        .arg_required_else_help(true)
}
