use clap::{arg, command, Command};

pub fn command() -> Command {
    command!("dotsec")
        .about("Manage secrets with encrypted .sec files")
        .author("JP Wesselink <jpwesselink@gmail.com>")
        .arg(arg!(-d --debug ... "Turn debugging information on"))
        .arg(
            arg!(-s --"sec-file" <FILE> "Sets a custom sec file")
                .global(true)
                .required(false)
                .env("SEC_FILE")
                .default_value(".sec"),
        )
}
