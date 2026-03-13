use std::time::Duration;

use aes_gcm::Aes256Gcm;
use aws_config::{meta::region::RegionProviderChain, BehaviorVersion};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use envelopers::{
    CacheOptions, CachingKeyWrapper, EncryptedRecord, EnvelopeCipher, KMSKeyProvider,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DataStoreError {
    #[error("encryption failed: {0}")]
    EncryptionError(#[from] envelopers::EncryptionError),
    #[error("decryption failed: {0}")]
    DecryptionError(#[from] envelopers::DecryptionError),
    #[error("base64 decoding failed: {0}")]
    DecodeError(#[from] base64::DecodeError),
}

async fn create_kms_cipher(
    key_id: &str,
    region: Option<&str>,
) -> EnvelopeCipher<CachingKeyWrapper<Aes256Gcm, KMSKeyProvider<Aes256Gcm>>> {
    let region_provider = match region {
        Some(r) => RegionProviderChain::default_provider()
            .or_else(aws_config::Region::new(r.to_string())),
        None => RegionProviderChain::default_provider(),
    };
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;
    let client = aws_sdk_kms::Client::new(&config);

    let provider = KMSKeyProvider::<Aes256Gcm>::new(client, key_id.to_string());
    EnvelopeCipher::init(CachingKeyWrapper::new(
        provider,
        CacheOptions::default()
            .with_max_age(Duration::from_secs(30))
            .with_max_bytes(100 * 1024)
            .with_max_messages(10)
            .with_max_entries(10),
    ))
}

/// Encrypt a raw string and return base64-encoded ciphertext.
pub async fn encrypt_raw(
    plaintext: &str,
    key_id: &str,
    region: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let cipher = create_kms_cipher(key_id, region).await;

    let encrypted = cipher
        .encrypt(plaintext.as_bytes())
        .await
        .map_err(DataStoreError::EncryptionError)?;
    let vec = encrypted.to_vec()?;
    Ok(STANDARD.encode(vec))
}

/// Decrypt base64-encoded ciphertext and return the plaintext string.
pub async fn decrypt_raw(
    ciphertext: &str,
    key_id: &str,
    region: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    let decoded = STANDARD.decode(ciphertext)?;
    let encrypted = EncryptedRecord::from_vec(decoded)
        .map_err(|e| format!("invalid encrypted record: {}", e))?;

    let cipher = create_kms_cipher(key_id, region).await;

    let decrypted = cipher
        .decrypt(&encrypted)
        .await
        .map_err(DataStoreError::DecryptionError)?;
    Ok(String::from_utf8(decrypted)?)
}
