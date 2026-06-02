use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    AeadCore, Aes256Gcm,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub mod local;
pub mod mac;

type HmacSha256 = Hmac<Sha256>;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    AesError(String),
    #[error("base64 decoding failed: {0}")]
    DecodeError(#[from] base64::DecodeError),
    #[error("invalid encrypted format")]
    InvalidFormat,
    #[error("key commitment verification failed")]
    KeyCommitmentFailed,
    /// File MAC verification failed — directives, values, or schema were
    /// tampered with between encryption and decryption.
    #[error("file MAC verification failed: directives or values modified after encryption")]
    MacMismatch,
}

/// Compute the v3 file-level MAC: HMAC-SHA256(dek, canonical_bytes).
///
/// `canonical_bytes` is the output of `crypto::mac::canonical_serialize`. The
/// 32-byte output is stored verbatim (base64-encoded) as `mac=...` inside the
/// `@dotsec(...)` directive on disk.
pub fn compute_file_mac(dek: &[u8], canonical: &[u8]) -> [u8; 32] {
    let mut hmac =
        <HmacSha256 as Mac>::new_from_slice(dek).expect("HMAC accepts any key length");
    hmac.update(canonical);
    hmac.finalize().into_bytes().into()
}

/// Constant-time MAC check. Returns `Err(CryptoError::MacMismatch)` on any
/// discrepancy — length mismatch or differing bytes.
pub fn verify_file_mac(dek: &[u8], canonical: &[u8], mac: &[u8]) -> Result<(), CryptoError> {
    let expected = compute_file_mac(dek, canonical);
    if expected.len() != mac.len() || expected.ct_eq(mac).unwrap_u8() != 1 {
        return Err(CryptoError::MacMismatch);
    }
    Ok(())
}

/// Compute a 32-byte key commitment: HMAC-SHA256(key=DEK, msg="dotsec-key-commit").
pub fn compute_key_commitment(dek: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(dek).expect("HMAC accepts any key length");
    mac.update(b"dotsec-key-commit");
    mac.finalize().into_bytes().to_vec()
}

/// Verify key commitment matches the DEK (constant-time comparison).
fn verify_key_commitment(dek: &[u8], commitment: &[u8]) -> Result<(), CryptoError> {
    let expected = compute_key_commitment(dek);
    if expected.len() != commitment.len() || expected.ct_eq(commitment).unwrap_u8() != 1 {
        return Err(CryptoError::KeyCommitmentFailed);
    }
    Ok(())
}

/// Pad plaintext with random bytes so ciphertext length doesn't leak value length.
/// Wire format: `[2-byte big-endian original length] [original data] [random padding]`
pub fn pad(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use rand::RngCore;

    if data.len() > u16::MAX as usize {
        return Err(CryptoError::AesError(format!(
            "value too large to pad: {} bytes exceeds maximum of {} bytes",
            data.len(),
            u16::MAX
        )));
    }

    let header_len = 2;
    let total = header_len + data.len();
    let base_padded = total.div_ceil(64) * 64;
    let extra_blocks = (OsRng.next_u32() % 2) as usize;
    let padded_len = base_padded + (extra_blocks * 64);

    let mut buf = vec![0u8; padded_len];
    OsRng.fill_bytes(&mut buf);
    let len = data.len() as u16;
    buf[0..2].copy_from_slice(&len.to_be_bytes());
    buf[2..2 + data.len()].copy_from_slice(data);
    Ok(buf)
}

/// Remove padding and return the original plaintext bytes.
pub fn unpad(data: &[u8]) -> Result<&[u8], CryptoError> {
    if data.len() < 2 {
        return Err(CryptoError::InvalidFormat);
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if 2 + len > data.len() {
        return Err(CryptoError::InvalidFormat);
    }
    Ok(&data[2..2 + len])
}

/// Encrypt a single value with AES-256-GCM using the given DEK.
/// Format: `ENC[base64(commitment || nonce || ciphertext || tag)]`
pub fn encrypt_value(plaintext: &str, dek: &[u8], aad: &str) -> Result<String, CryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(dek).map_err(|e| CryptoError::AesError(e.to_string()))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut padded = pad(plaintext.as_bytes())?;
    let commitment = compute_key_commitment(dek);

    let payload = Payload {
        msg: &padded,
        aad: aad.as_bytes(),
    };
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| CryptoError::AesError(e.to_string()))?;

    padded.zeroize();

    let mut blob = Vec::with_capacity(32 + 12 + ciphertext.len());
    blob.extend_from_slice(&commitment);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);

    Ok(format!("ENC[{}]", STANDARD.encode(&blob)))
}

/// Decrypt a value in `ENC[base64(...)]` format using the given DEK.
pub fn decrypt_value(enc_str: &str, dek: &[u8], aad: &str) -> Result<String, CryptoError> {
    let inner = enc_str
        .strip_prefix("ENC[")
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(CryptoError::InvalidFormat)?;

    let blob = STANDARD.decode(inner)?;
    if blob.len() < 32 + 12 + 16 {
        return Err(CryptoError::InvalidFormat);
    }

    let (commitment, rest) = blob.split_at(32);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    verify_key_commitment(dek, commitment)?;

    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    let cipher =
        Aes256Gcm::new_from_slice(dek).map_err(|e| CryptoError::AesError(e.to_string()))?;

    let payload = Payload {
        msg: ciphertext,
        aad: aad.as_bytes(),
    };
    let mut decrypted = cipher
        .decrypt(nonce, payload)
        .map_err(|e| CryptoError::AesError(e.to_string()))?;

    let plaintext = unpad(&decrypted)?.to_vec();
    decrypted.zeroize();

    String::from_utf8(plaintext).map_err(|e| CryptoError::AesError(e.to_string()))
}

/// Check if a value is in the `ENC[...]` envelope format.
pub fn is_encrypted_value(value: &str) -> bool {
    value.starts_with("ENC[") && value.ends_with(']')
}

/// Generate a random 32-byte AES-256 data encryption key.
pub fn generate_dek() -> Zeroizing<Vec<u8>> {
    use rand::RngCore;
    let mut dek = vec![0u8; 32];
    OsRng.fill_bytes(&mut dek);
    Zeroizing::new(dek)
}

#[cfg(test)]
mod file_mac_tests {
    use super::mac::{canonical_serialize, CanonicalEntry};
    use super::*;

    fn fixture() -> (Vec<u8>, Vec<u8>) {
        let dek = vec![0x42; 32];
        let canonical = canonical_serialize(
            &[("provider".into(), Some("local".into()))],
            &[CanonicalEntry {
                key: "FOO".into(),
                directives: vec![("encrypt".into(), None)],
                value: "ENC[abc]".into(),
            }],
            &[0u8; 32],
        );
        (dek, canonical)
    }

    #[test]
    fn roundtrip_compute_then_verify() {
        let (dek, canonical) = fixture();
        let mac = compute_file_mac(&dek, &canonical);
        verify_file_mac(&dek, &canonical, &mac).expect("verify must accept matching MAC");
    }

    #[test]
    fn verify_rejects_tampered_canonical_bytes() {
        let (dek, canonical) = fixture();
        let mac = compute_file_mac(&dek, &canonical);
        let mut tampered = canonical.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0x01;
        let err = verify_file_mac(&dek, &tampered, &mac);
        assert!(matches!(err, Err(CryptoError::MacMismatch)));
    }

    #[test]
    fn verify_rejects_wrong_dek() {
        let (dek, canonical) = fixture();
        let mac = compute_file_mac(&dek, &canonical);
        let wrong_dek = vec![0x99; 32];
        let err = verify_file_mac(&wrong_dek, &canonical, &mac);
        assert!(matches!(err, Err(CryptoError::MacMismatch)));
    }

    #[test]
    fn verify_rejects_truncated_mac() {
        let (dek, canonical) = fixture();
        let mac = compute_file_mac(&dek, &canonical);
        let err = verify_file_mac(&dek, &canonical, &mac[..16]);
        assert!(matches!(err, Err(CryptoError::MacMismatch)));
    }

    #[test]
    fn compute_is_deterministic() {
        let (dek, canonical) = fixture();
        let a = compute_file_mac(&dek, &canonical);
        let b = compute_file_mac(&dek, &canonical);
        assert_eq!(a, b);
    }

    #[test]
    fn different_canonicals_produce_different_macs() {
        let (dek, canonical_a) = fixture();
        let canonical_b = canonical_serialize(
            &[("provider".into(), Some("local".into()))],
            &[CanonicalEntry {
                key: "FOO".into(),
                directives: vec![("encrypt".into(), None)],
                // Different value — the MAC must reflect that.
                value: "ENC[xyz]".into(),
            }],
            &[0u8; 32],
        );
        let a = compute_file_mac(&dek, &canonical_a);
        let b = compute_file_mac(&dek, &canonical_b);
        assert_ne!(a, b);
    }
}
