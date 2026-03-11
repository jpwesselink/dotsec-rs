use clap::Command;

pub fn command() -> Command {
    Command::new("encrypt").about("Encrypts .env file")
}
