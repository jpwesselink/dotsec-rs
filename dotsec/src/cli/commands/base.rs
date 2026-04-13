use clap::{arg, command, Command};

pub fn command() -> Command {
    command!("dotsec")
        .about("Manage secrets with encrypted .sec files")
        .author("JP Wesselink <jpwesselink@gmail.com>")
        .after_help(
            "Quick start:\n  \
             dotsec set API_KEY sk-live-xxx --encrypt   # new project: auto-creates .sec + keypair\n  \
             dotsec set PORT 3000                       # add a plaintext variable\n  \
             dotsec run -- node server.js               # run with decrypted env vars injected\n\n\
             Docs: https://dotsec.dev",
        )
        .arg(arg!(-d --debug ... "Turn debugging information on"))
        .arg(
            arg!(-s --"sec-file" <FILE> "Sets a custom sec file")
                .global(true)
                .required(false)
                .env("SEC_FILE")
                .default_value(".sec"),
        )
        .arg(
            arg!(--"schema" <FILE> "Path to dotsec.schema file")
                .global(true)
                .required(false)
                .env("DOTSEC_SCHEMA"),
        )
}
