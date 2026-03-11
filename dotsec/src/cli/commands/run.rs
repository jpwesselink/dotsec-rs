use clap::{arg, value_parser, ArgAction, Command};
use dotsec::RunUsing;

pub fn command() -> Command {
    Command::new("run")
        .about("Runs commands in a separate process")
        .long_about("Runs commands in a separate process, using a sec or env file")
        .arg(arg!(--"no-redaction" "Redacts values").action(ArgAction::SetTrue))
        .arg(
            arg!(--"using" "Run using sec or env file, defaults to sec")
                .value_parser(value_parser!(RunUsing))
                .default_value("sec"),
        )
        .arg(arg!(<cmd> ... "c to run").trailing_var_arg(true))
}
