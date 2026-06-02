use dotsec::EncryptionEngine;

#[derive(Debug, Clone)]
pub struct DefaultOptions<'a> {
    pub sec_file: &'a str,
    pub encryption_engine: EncryptionEngine,
    pub schema_path: Option<String>,
    /// SHA-256 of the schema's canonical form (sorted directives, descriptions
    /// stripped), or the hash of empty bytes if no schema is in effect. Bound
    /// into v3 file MACs so a semantic schema change invalidates pre-existing
    /// MACs while cosmetic edits (description, ordering, whitespace) don't.
    pub schema_hash: [u8; 32],
}
