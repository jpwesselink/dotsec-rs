use aws_config::{meta::region::RegionProviderChain, BehaviorVersion};
use thiserror::Error;
use zeroize::Zeroizing;

// Re-export shared crypto functions so existing callers (dotsec-core) don't break
pub use crypto::{decrypt_value, encrypt_value, is_encrypted_value, pad, unpad, CryptoError};

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
    #[error("file MAC verification failed: directives or values modified after encryption")]
    MacMismatch,
}

impl From<CryptoError> for DataStoreError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::AesError(msg) => DataStoreError::AesError(msg),
            CryptoError::DecodeError(e) => DataStoreError::DecodeError(e),
            CryptoError::InvalidFormat => DataStoreError::InvalidFormat,
            CryptoError::KeyCommitmentFailed => DataStoreError::KeyCommitmentFailed,
            CryptoError::MacMismatch => DataStoreError::MacMismatch,
        }
    }
}

/// Redact AWS resource identifiers — ARNs and 12-digit account IDs — from
/// an error message before it bubbles up into the application's error
/// chain. The AWS SDK's error formatters routinely include the calling
/// principal's ARN, the target resource ARN, and the account ID, all of
/// which the user doesn't necessarily want appearing in CI logs or `dotsec
/// run` stderr.
///
/// Conservative: replace any `arn:aws:…` token (terminated by whitespace,
/// quote, comma, or end-of-string) with `arn:aws:[REDACTED]`, and any
/// stand-alone 12-digit number with `[ACCOUNT]`. Leaves the error type
/// name and the human-readable message intact so the user still knows
/// what kind of failure it is.
pub fn sanitize_aws_error(input: String) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // ARN: "arn:aws:..." up to a terminator.
        if bytes[i..].starts_with(b"arn:aws:") {
            out.push_str("arn:aws:[REDACTED]");
            i += "arn:aws:".len();
            while i < bytes.len() && !matches!(bytes[i], b' ' | b'\t' | b'\n' | b'"' | b'\'' | b',')
            {
                i += 1;
            }
            continue;
        }
        // 12-digit standalone number (account ID). Require non-digit boundaries
        // on both sides so we don't mangle, e.g., a 12-byte hash that happens
        // to be all digits or a longer number.
        if bytes[i].is_ascii_digit()
            && (i == 0 || !bytes[i - 1].is_ascii_digit())
            && i + 12 <= bytes.len()
            && bytes[i..i + 12].iter().all(|b| b.is_ascii_digit())
            && (i + 12 == bytes.len() || !bytes[i + 12].is_ascii_digit())
        {
            out.push_str("[ACCOUNT]");
            i += 12;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

async fn create_kms_client(region: Option<&str>) -> aws_sdk_kms::Client {
    let region_provider = match region {
        Some(r) => {
            RegionProviderChain::default_provider().or_else(aws_config::Region::new(r.to_string()))
        }
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
                .ok_or_else(|| DataStoreError::KmsError("key metadata missing ARN".into()))?
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
                Err(DataStoreError::KmsError(sanitize_aws_error(
                    err.to_string(),
                )))
            }
        }
    }
}

/// Create a new KMS key and associate an alias with it.
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
        .map_err(|e| DataStoreError::KmsError(sanitize_aws_error(e.to_string())))?;

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
        .map_err(|e| DataStoreError::KmsError(sanitize_aws_error(e.to_string())))?;

    Ok(key_arn)
}

/// EncryptionContext entries bound to every KMS `GenerateDataKey` and
/// `Decrypt` call that wraps/unwraps a DEK. The context is symmetric:
/// `Decrypt` MUST be called with the same context that was passed to
/// `GenerateDataKey`, otherwise KMS refuses to unwrap.
///
/// Today we only bind `dotsec:format=v3` — a format-confusion guard. The
/// real protection lands when callers can write IAM policies pinning
/// `dotsec:format=v3` to specific roles (and CloudTrail logs the context
/// on every Decrypt for audit).
///
/// Why `dotsec:` prefix: KMS contexts are an unstructured `Map<String, String>`,
/// so unique namespacing prevents accidental collisions with whatever else
/// the user's IAM policies bind on the same KMS key.
pub type EncryptionContext = Vec<(String, String)>;

/// Generate a new AES-256 data encryption key via KMS, binding the given
/// `EncryptionContext`. The wrapped DEK can only be unwrapped later with
/// the same context.
///
/// **Coverage:**
/// - Type-level: `dotsec-core` pins the context shape via
///   `kms_encryption_context_pins_format_v3`.
/// - Wire-level: `aws/tests/localstack_kms.rs` runs the round-trip
///   (`generate → unwrap` matching context; `unwrap` mismatched / missing
///   context must error) against LocalStack. Gated on `#[ignore]` because
///   it needs docker; CI invokes it explicitly with `--ignored`. The
///   earlier blocker — `aws-smithy-mocks` pulling a conflicting
///   `aws-smithy-runtime` rev — is sidestepped by running real KMS on
///   LocalStack instead of mocking the SDK layer.
pub async fn generate_data_key(
    key_id: &str,
    region: Option<&str>,
    context: &EncryptionContext,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), Box<dyn std::error::Error>> {
    let client = create_kms_client(region).await;
    let mut req = client
        .generate_data_key()
        .key_id(key_id)
        .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256);
    for (k, v) in context {
        req = req.encryption_context(k, v);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| DataStoreError::KmsError(sanitize_aws_error(e.to_string())))?;

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

    Ok((Zeroizing::new(plaintext), wrapped))
}

/// Unwrap a KMS-encrypted data key back to plaintext. The `context` must
/// match what was passed to `generate_data_key` (or KMS rejects with
/// `InvalidCiphertextException`).
pub async fn unwrap_data_key(
    wrapped_dek: &[u8],
    region: Option<&str>,
    context: &EncryptionContext,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let client = create_kms_client(region).await;
    let mut req = client
        .decrypt()
        .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(wrapped_dek));
    for (k, v) in context {
        req = req.encryption_context(k, v);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| DataStoreError::KmsError(sanitize_aws_error(e.to_string())))?;

    let plaintext = resp
        .plaintext()
        .ok_or_else(|| DataStoreError::KmsError("no plaintext in decrypt response".into()))?
        .as_ref()
        .to_vec();

    Ok(Zeroizing::new(plaintext))
}

// --- Push to AWS services ---

async fn create_ssm_client(region: Option<&str>) -> aws_sdk_ssm::Client {
    let region_provider = match region {
        Some(r) => {
            RegionProviderChain::default_provider().or_else(aws_config::Region::new(r.to_string()))
        }
        None => RegionProviderChain::default_provider(),
    };
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;
    aws_sdk_ssm::Client::new(&config)
}

async fn create_secrets_manager_client(region: Option<&str>) -> aws_sdk_secretsmanager::Client {
    let region_provider = match region {
        Some(r) => {
            RegionProviderChain::default_provider().or_else(aws_config::Region::new(r.to_string()))
        }
        None => RegionProviderChain::default_provider(),
    };
    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;
    aws_sdk_secretsmanager::Client::new(&config)
}

/// Push a value to AWS SSM Parameter Store.
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
        .map_err(|e| DataStoreError::SsmError(sanitize_aws_error(e.to_string())))?;

    Ok(())
}

/// Push a value to AWS Secrets Manager.
pub async fn push_to_secrets_manager(
    name: &str,
    value: &str,
    region: Option<&str>,
) -> Result<(), DataStoreError> {
    let client = create_secrets_manager_client(region).await;

    let result = client
        .put_secret_value()
        .secret_id(name)
        .secret_string(value)
        .send()
        .await;

    match result {
        Ok(_) => Ok(()),
        Err(err) => {
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
                    .map_err(|e| {
                        DataStoreError::SecretsManagerError(sanitize_aws_error(e.to_string()))
                    })?;
                Ok(())
            } else {
                Err(DataStoreError::SecretsManagerError(sanitize_aws_error(
                    err.to_string(),
                )))
            }
        }
    }
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
        assert!(decrypt_value(&encrypted, &dek, "DB_PASSWORD").is_err());
    }

    #[test]
    fn decrypt_wrong_key_fails_commitment() {
        let dek1 = [0x42u8; 32];
        let dek2 = [0x43u8; 32];
        let encrypted = encrypt_value("secret", &dek1, "KEY").unwrap();
        let err = decrypt_value(&encrypted, &dek2, "KEY").unwrap_err();
        assert!(matches!(err, CryptoError::KeyCommitmentFailed));
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
    fn sanitize_strips_kms_arn() {
        let raw = "AccessDenied: User: arn:aws:iam::123456789012:user/alice is not authorized to perform: kms:Decrypt on resource: arn:aws:kms:us-east-1:123456789012:key/abcd-1234".to_string();
        let cleaned = sanitize_aws_error(raw);
        // Account ID is embedded inside both ARNs — the ARN replacement
        // collapses those entirely, so the account ID disappears as a
        // side effect (no separate `[ACCOUNT]` token needed here).
        assert!(!cleaned.contains("123456789012"));
        assert!(!cleaned.contains("user/alice"));
        assert!(!cleaned.contains("abcd-1234"));
        assert!(cleaned.contains("arn:aws:[REDACTED]"));
        assert!(cleaned.starts_with("AccessDenied: User: "));
        assert!(cleaned.contains("not authorized to perform: kms:Decrypt"));
    }

    #[test]
    fn sanitize_strips_standalone_account_id() {
        // The 12-digit `[ACCOUNT]` token kicks in when an account number
        // appears outside an ARN context — common in CloudTrail snippets
        // or hand-rolled error messages.
        let raw = "operation failed for account 123456789012 in region us-east-1".to_string();
        let cleaned = sanitize_aws_error(raw);
        assert!(!cleaned.contains("123456789012"));
        assert!(cleaned.contains("[ACCOUNT]"));
        assert_eq!(
            cleaned,
            "operation failed for account [ACCOUNT] in region us-east-1"
        );
    }

    #[test]
    fn sanitize_strips_arn_at_quote_boundary() {
        let raw = r#"error: "arn:aws:kms:us-east-1:111122223333:key/key-id-here""#.to_string();
        let cleaned = sanitize_aws_error(raw);
        assert!(!cleaned.contains("111122223333"));
        assert!(!cleaned.contains("key-id-here"));
        assert_eq!(cleaned, r#"error: "arn:aws:[REDACTED]""#);
    }

    #[test]
    fn sanitize_leaves_unrelated_numbers_alone() {
        // 12-digit account requires non-digit neighbors on both sides. A
        // 13- or 15-digit number must NOT match.
        let raw = "size: 1234567890123 bytes; rev: 1234567890".to_string();
        let cleaned = sanitize_aws_error(raw.clone());
        assert_eq!(cleaned, raw, "non-12-digit numbers must pass through");
    }

    #[test]
    fn sanitize_preserves_kms_action_name() {
        // The action name `kms:Decrypt` contains a colon and could be
        // confused with an ARN-shaped fragment by a naive impl. Ensure
        // we only strip on `arn:aws:` prefix specifically.
        let raw = "AccessDenied: principal not authorized to perform kms:Decrypt".to_string();
        let cleaned = sanitize_aws_error(raw.clone());
        assert_eq!(cleaned, raw);
    }

    #[test]
    fn sanitize_handles_empty_and_short_input() {
        assert_eq!(sanitize_aws_error(String::new()), "");
        assert_eq!(sanitize_aws_error("nope".to_string()), "nope");
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
        let a = crypto::compute_key_commitment(&dek);
        let b = crypto::compute_key_commitment(&dek);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn key_commitment_differs_per_key() {
        let a = crypto::compute_key_commitment(&[0x42u8; 32]);
        let b = crypto::compute_key_commitment(&[0x43u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn pad_rejects_oversized_input() {
        let data = vec![0u8; 65536];
        let result = pad(&data);
        assert!(
            result.is_err(),
            "pad should reject data larger than u16::MAX bytes"
        );
    }

    #[test]
    fn pad_accepts_max_size() {
        let data = vec![0u8; 65535];
        let result = pad(&data);
        assert!(
            result.is_ok(),
            "pad should accept data of exactly u16::MAX bytes"
        );
    }
}
