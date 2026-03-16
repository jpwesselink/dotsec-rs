use clap::ValueEnum;

#[derive(Clone, Debug, ValueEnum, Default)]
pub enum OutputFormat {
    #[default]
    Raw,
    Json,
    Text,
    Csv,
}
