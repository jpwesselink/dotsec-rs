use dotsec::EncryptionEngine;

#[derive(Debug, Clone)]
pub struct DefaultOptions<'a> {
    pub sec_file: &'a str,
    pub encryption_engine: EncryptionEngine,
    pub schema_path: Option<String>,
}
