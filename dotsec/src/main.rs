#[cfg(feature = "cli")]
use crate::cli::parse_args;
use colored::Colorize;

mod cli;
mod default_options;

#[tokio::main]
async fn main() {
    env_logger::init();

    match parse_args().await {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);

            let mut source = e.source();
            while let Some(cause) = source {
                eprintln!("  {} {}", "caused by:".red(), cause);
                source = cause.source();
            }

            std::process::exit(1);
        }
    }
}
