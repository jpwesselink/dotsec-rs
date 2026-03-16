/// Internal encryption engine used for dispatch.
#[derive(Clone, Debug, Default)]
pub enum EncryptionEngine {
    Aws(AwsEncryptionOptions),
    #[default]
    None,
}

#[derive(Clone, Debug, Default)]
pub struct AwsEncryptionOptions {
    pub key_id: Option<String>,
    pub region: Option<String>,
}

impl From<dotenv::FileConfig> for EncryptionEngine {
    fn from(config: dotenv::FileConfig) -> Self {
        match config.provider.as_deref() {
            Some("aws") => EncryptionEngine::Aws(AwsEncryptionOptions {
                key_id: config.key_id,
                region: config.region,
            }),
            _ => EncryptionEngine::None,
        }
    }
}
