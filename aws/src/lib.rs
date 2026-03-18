use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    AeadCore, Aes256Gcm,
};
use aws_config::{meta::region::RegionProviderChain, BehaviorVersion};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

#[derive(Error, Debug)]
pub enum DataStoreError {
    #[error("encryption failed: {0}")]
    AesError(String),
    #[error("KMS error: {0}")]
    KmsError(String),
    #[error("base64 decoding failed: {0}")]
    DecodeError(#[from] base64::DecodeError),
    #[error("invalid encrypted format")]
    InvalidFormat,
    #[error("key commitment verification failed")]
    KeyCommitmentFailed,
    #[error("SSM error: {0}")]
    SsmError(String),
    #[error("Secrets Manager error: {0}")]
    SecretsManagerError(String),
}

async fn create_kms_client(region: Option<&str>) -> aws_sdk_kms::Client {
    let region_provider = match region {
        Some(r) => RegionProviderChain::default_provider()
            .or_else(aws_config::Region::new(r.to_string())),
        None => RegionProviderChain::default_provider(),
    };
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;
    aws_sdk_kms::Client::new(&config)
}

/// Check if a KMS key alias exists. Returns the key ARN if found.
pub async fn check_key_alias(
    alias: &str,
    region: Option<&str>,
) -> Result<Option<String>, DataStoreError> {
    let client = create_kms_client(region).await;
    match client.describe_key().key_id(alias).send().await {
        Ok(resp) => {
            let arn = resp
                .key_metadata()
                .and_then(|m| m.arn())
                .unwrap_or_default()
                .to_string();
            Ok(Some(arn))
        }
        Err(err) => {
            let is_not_found = err
                .as_service_error()
                .is_some_and(|e| e.is_not_found_exception());
            if is_not_found {
                Ok(None)
            } else {
                Err(DataStoreError::KmsError(err.to_string()))
            }
        }
    }
}

/// Create a new KMS key and associate an alias with it.
/// Returns the key ARN.
pub async fn create_key_with_alias(
    alias: &str,
    region: Option<&str>,
) -> Result<String, DataStoreError> {
    let client = create_kms_client(region).await;

    let key_resp = client
        .create_key()
        .description("Created by dotsec")
        .send()
        .await
        .map_err(|e| DataStoreError::KmsError(e.to_string()))?;

    let metadata = key_resp
        .key_metadata()
        .ok_or_else(|| DataStoreError::KmsError("no key metadata in response".into()))?;

    let key_id = metadata.key_id().to_string();
    let key_arn = metadata.arn().unwrap_or(&key_id).to_string();

    client
        .create_alias()
        .alias_name(alias)
        .target_key_id(&key_id)
        .send()
        .await
        .map_err(|e| DataStoreError::KmsError(e.to_string()))?;

    Ok(key_arn)
}

/// Generate a new AES-256 data encryption key via KMS.
/// Returns (plaintext_dek, wrapped_dek) where wrapped_dek is KMS-encrypted.
pub async fn generate_data_key(
    key_id: &str,
    region: Option<&str>,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let client = create_kms_client(region).await;
    let resp = client
        .generate_data_key()
        .key_id(key_id)
        .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
        .send()
        .await
        .map_err(|e| DataStoreError::KmsError(e.to_string()))?;

    let plaintext = resp
        .plaintext()
        .ok_or_else(|| DataStoreError::KmsError("no plaintext in response".into()))?
        .as_ref()
        .to_vec();

    let wrapped = resp
        .ciphertext_blob()
        .ok_or_else(|| DataStoreError::KmsError("no ciphertext_blob in response".into()))?
        .as_ref()
        .to_vec();

    Ok((plaintext, wrapped))
}

/// Unwrap a KMS-encrypted data key back to plaintext.
pub async fn unwrap_data_key(
    wrapped_dek: &[u8],
    region: Option<&str>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let client = create_kms_client(region).await;
    let resp = client
        .decrypt()
        .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(wrapped_dek))
        .send()
        .await
        .map_err(|e| DataStoreError::KmsError(e.to_string()))?;

    let plaintext = resp
        .plaintext()
        .ok_or_else(|| DataStoreError::KmsError("no plaintext in decrypt response".into()))?
        .as_ref()
        .to_vec();

    Ok(plaintext)
}

/// Compute a 32-byte key commitment: HMAC-SHA256(key=DEK, msg="dotsec-key-commit").
/// Stored alongside ciphertext to prove which key encrypted it.
fn compute_key_commitment(dek: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(dek).expect("HMAC accepts any key length");
    mac.update(b"dotsec-key-commit");
    mac.finalize().into_bytes().to_vec()
}

/// Verify key commitment matches the DEK.
fn verify_key_commitment(dek: &[u8], commitment: &[u8]) -> Result<(), DataStoreError> {
    let expected = compute_key_commitment(dek);
    if expected.as_slice() != commitment {
        return Err(DataStoreError::KeyCommitmentFailed);
    }
    Ok(())
}

/// Pad plaintext with random bytes so ciphertext length doesn't leak
/// the original value length. Adds 0–1 extra 64-byte blocks randomly,
/// so the same plaintext can land in different length buckets across
/// re-encryptions.
fn pad(data: &[u8]) -> Vec<u8> {
    use rand::RngCore;

    // Format: [2-byte big-endian original length] [original data] [random padding]
    let header_len = 2;
    let total = header_len + data.len();
    let base_padded = total.div_ceil(64) * 64;

    // Add 0–1 extra 64-byte blocks randomly
    let extra_blocks = (OsRng.next_u32() % 2) as usize;
    let padded_len = base_padded + (extra_blocks * 64);

    let mut buf = vec![0u8; padded_len];
    OsRng.fill_bytes(&mut buf); // fill everything with random bytes first
    let len = data.len() as u16;
    buf[0..2].copy_from_slice(&len.to_be_bytes());
    buf[2..2 + data.len()].copy_from_slice(data);
    buf
}

/// Remove padding and return the original plaintext bytes.
fn unpad(data: &[u8]) -> Result<&[u8], DataStoreError> {
    if data.len() < 2 {
        return Err(DataStoreError::InvalidFormat);
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if 2 + len > data.len() {
        return Err(DataStoreError::InvalidFormat);
    }
    Ok(&data[2..2 + len])
}

/// Encrypt a single value with AES-256-GCM using the given DEK.
///
/// The variable name is used as AAD (additional authenticated data),
/// binding the ciphertext to its key name — prevents swapping encrypted
/// values between variables.
///
/// Format: `ENC[base64(commitment || nonce || ciphertext || tag)]`
/// - commitment: 32 bytes (HMAC-SHA256 key commitment)
/// - nonce: 12 bytes
/// - ciphertext + tag: variable length (padded plaintext + 16-byte GCM tag)
pub fn encrypt_value(plaintext: &str, dek: &[u8], aad: &str) -> Result<String, DataStoreError> {
    let cipher =
        Aes256Gcm::new_from_slice(dek).map_err(|e| DataStoreError::AesError(e.to_string()))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut padded = pad(plaintext.as_bytes());
    let commitment = compute_key_commitment(dek);

    let payload = Payload {
        msg: &padded,
        aad: aad.as_bytes(),
    };
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| DataStoreError::AesError(e.to_string()))?;

    padded.zeroize();

    // commitment (32 bytes) || nonce (12 bytes) || ciphertext+tag
    let mut blob = Vec::with_capacity(32 + 12 + ciphertext.len());
    blob.extend_from_slice(&commitment);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);

    Ok(format!("ENC[{}]", STANDARD.encode(&blob)))
}

/// Decrypt a value in `ENC[base64(...)]` format using the given DEK.
///
/// The variable name must be provided as AAD — must match what was used
/// during encryption or decryption will fail (GCM authentication check).
pub fn decrypt_value(enc_str: &str, dek: &[u8], aad: &str) -> Result<String, DataStoreError> {
    let inner = enc_str
        .strip_prefix("ENC[")
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(DataStoreError::InvalidFormat)?;

    let blob = STANDARD.decode(inner)?;
    // commitment (32) + nonce (12) + at least 16 bytes (GCM tag)
    if blob.len() < 32 + 12 + 16 {
        return Err(DataStoreError::InvalidFormat);
    }

    let (commitment, rest) = blob.split_at(32);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    // Verify key commitment before attempting decryption
    verify_key_commitment(dek, commitment)?;

    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    let cipher =
        Aes256Gcm::new_from_slice(dek).map_err(|e| DataStoreError::AesError(e.to_string()))?;

    let payload = Payload {
        msg: ciphertext,
        aad: aad.as_bytes(),
    };
    let mut decrypted = cipher
        .decrypt(nonce, payload)
        .map_err(|e| DataStoreError::AesError(e.to_string()))?;

    let plaintext = unpad(&decrypted)?.to_vec();
    decrypted.zeroize();

    String::from_utf8(plaintext).map_err(|e| DataStoreError::AesError(e.to_string()))
}

// --- Push to AWS services ---

async fn create_ssm_client(region: Option<&str>) -> aws_sdk_ssm::Client {
    let region_provider = match region {
        Some(r) => RegionProviderChain::default_provider()
            .or_else(aws_config::Region::new(r.to_string())),
        None => RegionProviderChain::default_provider(),
    };
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;
    aws_sdk_ssm::Client::new(&config)
}

async fn create_secrets_manager_client(
    region: Option<&str>,
) -> aws_sdk_secretsmanager::Client {
    let region_provider = match region {
        Some(r) => RegionProviderChain::default_provider()
            .or_else(aws_config::Region::new(r.to_string())),
        None => RegionProviderChain::default_provider(),
    };
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;
    aws_sdk_secretsmanager::Client::new(&config)
}

/// Push a value to AWS SSM Parameter Store.
/// Uses SecureString for sensitive values, String for plaintext.
pub async fn push_to_ssm(
    name: &str,
    value: &str,
    secure: bool,
    region: Option<&str>,
) -> Result<(), DataStoreError> {
    let client = create_ssm_client(region).await;
    let param_type = if secure {
        aws_sdk_ssm::types::ParameterType::SecureString
    } else {
        aws_sdk_ssm::types::ParameterType::String
    };

    client
        .put_parameter()
        .name(name)
        .value(value)
        .r#type(param_type)
        .overwrite(true)
        .send()
        .await
        .map_err(|e| DataStoreError::SsmError(e.to_string()))?;

    Ok(())
}

/// Push a value to AWS Secrets Manager.
/// Creates the secret if it doesn't exist, updates it if it does.
pub async fn push_to_secrets_manager(
    name: &str,
    value: &str,
    region: Option<&str>,
) -> Result<(), DataStoreError> {
    let client = create_secrets_manager_client(region).await;

    // Try updating first
    let result = client
        .put_secret_value()
        .secret_id(name)
        .secret_string(value)
        .send()
        .await;

    match result {
        Ok(_) => Ok(()),
        Err(err) => {
            // If the secret doesn't exist, create it
            let is_not_found = err
                .as_service_error()
                .is_some_and(|e| e.is_resource_not_found_exception());

            if is_not_found {
                client
                    .create_secret()
                    .name(name)
                    .secret_string(value)
                    .send()
                    .await
                    .map_err(|e| DataStoreError::SecretsManagerError(e.to_string()))?;
                Ok(())
            } else {
                Err(DataStoreError::SecretsManagerError(err.to_string()))
            }
        }
    }
}

/// Check if a value is in the `ENC[...]` envelope format.
pub fn is_encrypted_value(value: &str) -> bool {
    value.starts_with("ENC[") && value.ends_with(']')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let dek = [0x42u8; 32];
        let plaintext = "hello world secret";
        let aad = "API_KEY";
        let encrypted = encrypt_value(plaintext, &dek, aad).unwrap();
        assert!(encrypted.starts_with("ENC["));
        assert!(encrypted.ends_with(']'));
        let decrypted = decrypt_value(&encrypted, &dek, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_produces_different_ciphertexts() {
        let dek = [0x42u8; 32];
        let plaintext = "same input";
        let a = encrypt_value(plaintext, &dek, "KEY").unwrap();
        let b = encrypt_value(plaintext, &dek, "KEY").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn decrypt_wrong_aad_fails() {
        let dek = [0x42u8; 32];
        let encrypted = encrypt_value("secret", &dek, "API_KEY").unwrap();
        // Decrypting with different AAD must fail
        assert!(decrypt_value(&encrypted, &dek, "DB_PASSWORD").is_err());
    }

    #[test]
    fn decrypt_wrong_key_fails_commitment() {
        let dek1 = [0x42u8; 32];
        let dek2 = [0x43u8; 32];
        let encrypted = encrypt_value("secret", &dek1, "KEY").unwrap();
        let err = decrypt_value(&encrypted, &dek2, "KEY").unwrap_err();
        assert!(matches!(err, DataStoreError::KeyCommitmentFailed));
    }

    #[test]
    fn decrypt_invalid_format() {
        let dek = [0x42u8; 32];
        assert!(decrypt_value("not encrypted", &dek, "").is_err());
        assert!(decrypt_value("ENC[]", &dek, "").is_err());
        assert!(decrypt_value("ENC[dG9vc2hvcnQ=]", &dek, "").is_err());
    }

    #[test]
    fn is_encrypted_value_checks() {
        assert!(is_encrypted_value("ENC[abc123]"));
        assert!(!is_encrypted_value("plaintext"));
        assert!(!is_encrypted_value("ENC[no closing"));
        assert!(!is_encrypted_value("prefix ENC[abc]"));
    }

    #[test]
    fn encrypt_empty_string() {
        let dek = [0x42u8; 32];
        let encrypted = encrypt_value("", &dek, "EMPTY").unwrap();
        let decrypted = decrypt_value(&encrypted, &dek, "EMPTY").unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn encrypt_unicode() {
        let dek = [0x42u8; 32];
        let plaintext = "héllo wörld 🔑";
        let encrypted = encrypt_value(plaintext, &dek, "UNI").unwrap();
        let decrypted = decrypt_value(&encrypted, &dek, "UNI").unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn key_commitment_deterministic() {
        let dek = [0x42u8; 32];
        let a = compute_key_commitment(&dek);
        let b = compute_key_commitment(&dek);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn key_commitment_differs_per_key() {
        let a = compute_key_commitment(&[0x42u8; 32]);
        let b = compute_key_commitment(&[0x43u8; 32]);
        assert_ne!(a, b);
    }
}
