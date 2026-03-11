use dotsec::EncryptionEngine;

#[derive(Debug, Clone)]
pub struct DefaultOptions<'a> {
    // env_file Option<String>
    pub env_file: Option<&'a String>,
    // sec_file Option<String>
    pub sec_file: Option<&'a String>,
    // encrytion_engine EncryptionEngine
    pub encryption_engine: EncryptionEngine,
}
