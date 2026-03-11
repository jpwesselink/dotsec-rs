use std::io::{Error, ErrorKind};

use colored::Colorize;
use log::debug;

// load env file using tokio
pub async fn load_file(filename: &str) -> Result<String, std::io::Error> {
    // use unwrap_or to set default value
    debug!("Loading {} file", filename.yellow());

    // check if file exists, if not return error saying file does not exist
    let file_exists = tokio::fs::metadata(filename).await.is_ok();
    if !file_exists {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("{} does not exist", filename.red()),
        ));
    }

    let raw_dot_env = tokio::fs::read_to_string(filename)
        .await
        .expect("Could not read file");
    Ok(raw_dot_env)
}

// write env file using tokio
pub async fn write_file(filename: &str, contents: &str) -> Result<(), std::io::Error> {
    // if log_level is verbose or on, print filename
    debug!("Writing {} file", filename.yellow());

    tokio::fs::write(filename, contents).await?;
    Ok(())
}
