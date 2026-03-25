/// Internal encryption engine used for dispatch.
#[derive(Clone, Debug, Default)]
pub enum EncryptionEngine {
    Aws(AwsEncryptionOptions),
    #[default]
    None,
}

#[derive(Clone, Default)]
pub struct AwsEncryptionOptions {
    pub key_id: Option<String>,
    pub region: Option<String>,
}

impl std::fmt::Debug for AwsEncryptionOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsEncryptionOptions")
            .field("key_id", &self.key_id.as_ref().map(|_| "[REDACTED]"))
            .field("region", &self.region)
            .finish()
    }
}

impl From<dotenv::FileConfig> for EncryptionEngine {
    fn from(config: dotenv::FileConfig) -> Self {
        match config.provider.as_deref() {
            Some("aws") => EncryptionEngine::Aws(AwsEncryptionOptions {
                key_id: config.key_id,
                region: config.region,
            }),
            Some(unknown) => {
                eprintln!("\x1b[1;31mERROR\x1b[0m: unknown encryption provider '{}', expected 'aws'. Encryption is DISABLED.", unknown);
                EncryptionEngine::None
            }
            None => EncryptionEngine::None,
        }
    }
}
