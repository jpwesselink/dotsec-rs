use clap::{arg, command, value_parser, Command, ValueEnum};
use dotsec::ChangeCase;
use std::path::PathBuf;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum EncryptionEngine {
    Aws,
}

pub fn command() -> Command {
    command!("dotsec")
        .about("A tool for encrypting and decrypting .env files")
        .author("JP Wesselink <jpwesselink@gmail.com>")
        .arg(
            arg!(
                -c --config <FILE> "Sets a custom config file"
            )
            .global(true)
            .required(false)
            .env("DOTSEC_CONFIG")
            .value_parser(value_parser!(PathBuf)),
        )
        .arg(arg!(
            -d --debug ... "Turn debugging information on"
        ))
        .arg(
            arg!(
                -e --"env-file" <FILE> "Sets a custom env file"
            )
            .global(true)
            .required(false)
            .env("DOTSEC_ENV_FILE")
            .default_value(".env"),
        )
        .arg(
            arg!(
            -s  --"sec-file" <FILE> "Sets a custom sec file"
                         )
            .global(true)
            .required(false)
            .env("DOTSEC_SEC_FILE")
            .default_value(".sec"),
        )
        .arg(
            arg!(-E --"encryption-engine" <ENGINE> "Selects an encryption engine, defaults to aws")
                .value_parser(value_parser!(EncryptionEngine))
                .global(true)
                .env("DOTSEC_ENCRYPTION_ENGINE")
                .default_value("aws")
                .required(false),
        )
        .arg(
            arg!(
                -k --"aws-key-id" <FILE> "Sets a AWS key id, defaults to alias/dotsec"
            )
            .global(true)
            .env("DOTSEC_AWS_KEY_ID")
            .default_value("alias/dotsec")
            .required(false),
        )
        .arg(
            arg!(--"aws-sm-change-case" <FILE> "Sets a AWS key id, defaults to alias/dotsec")
                .value_parser(value_parser!(ChangeCase))
                .env("DOTSEC_AWS_SECRETS_MANAGER_CHANGE_CASE")
                .default_value("camel-case")
                .required(false),
        )
}
