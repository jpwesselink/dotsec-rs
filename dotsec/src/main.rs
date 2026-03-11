#[cfg(feature = "cli")]
use crate::cli::parse_args;
use colored::Colorize;

mod cli;
mod default_options;
mod fs;

pub fn get_error_chain(e: &Box<dyn std::error::Error>) -> Vec<String> {
    let mut fml: Vec<String> = Vec::new();
    let mut source = e.source();
    while let Some(e) = source {
        fml.push(e.to_string());
        source = e.source();
    }

    return fml;
}

#[tokio::main]
async fn main() {
    env_logger::init();

    match parse_args().await {
        Ok(_) => {}
        Err(e) => {
            let error_chain = get_error_chain(&e);
            eprintln!(
                "{} {}",
                "An error occurred".to_string().red(),
                e.to_string().yellow()
            );
            // if log level is set to debug, then print the last error in the chain
            if log::max_level() == log::LevelFilter::Debug {
                // get the last error in the chain, first check if the chain is empty
                if !error_chain.is_empty() {
                    let last_error = error_chain.last().expect("error chain is empty");
                    eprintln!("{}", last_error.red());
                }
            }

            // if log level is set to trace, print the whole chain
            if log::max_level() == log::LevelFilter::Trace {
                // like `- {message}\n`
                let pretty_error_chain = error_chain.join("\n");
                eprintln!("{}", pretty_error_chain.red());
            }

            std::process::exit(1);
        }
    }
}
