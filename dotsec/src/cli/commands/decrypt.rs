use clap::Command;

pub fn command() -> Command {
    Command::new("decrypt").about("Decrypts .env file")
}
