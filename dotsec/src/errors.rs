use thiserror::Error;


#[derive(Error, Debug)]
pub enum DotsecError {
    #[error("data store disconnected")]
    CliError(#[from] clap::Error),
    // #[error("the data for key `{0}` is not available")]
    // Redaction(String),
    // #[error("invalid header (expected {expected:?}, found {found:?})")]
    // InvalidHeader { expected: String, found: String },
    // #[error("unknown data store error")]
    // Unknown,
}