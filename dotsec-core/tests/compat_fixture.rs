//! End-to-end format compatibility: `tests/fixtures/v7/compat.sec` was
//! encrypted by dotsec 7.x (aes-gcm 0.10, hmac 0.12, sha2 0.10, age 0.11)
//! with the local provider. It must keep decrypting — including the v3
//! file-MAC check — with whatever dependency versions we're on now.
//!
//! DO NOT regenerate the fixture to make this pass: a failure means existing
//! users' `.sec` files would stop decrypting. `compat.sec.key` is a throwaway
//! test identity, not a real secret.

use dotenv::Line;
use dotsec_core::*;

#[tokio::test]
async fn v7_fixture_still_decrypts_and_verifies() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v7");
    let sec = dir.join("compat.sec").to_string_lossy().to_string();
    let key = dir.join("compat.sec.key").to_string_lossy().to_string();
    let engine = EncryptionEngine::Local(LocalEncryptionOptions {
        key_file: Some(key),
    });

    let lines = decrypt_sec_to_lines(&sec, &engine, &crypto::mac::empty_schema_hash())
        .await
        .expect("v7 fixture must decrypt and pass the file MAC");

    let got: Vec<(String, String)> = lines
        .into_iter()
        .filter_map(|l| match l {
            Line::Kv { key, value, .. } => Some((key, value)),
            _ => None,
        })
        .collect();
    let want: Vec<(&str, String)> = vec![
        ("EMPTY", String::new()),
        ("SHORT", "x".into()),
        ("PAD_EDGE_62", "a".repeat(62)),
        ("PAD_EDGE_63", "b".repeat(63)),
        ("LONG", "0123456789".repeat(30)),
        ("UNICODE", "héllo wörld — 秘密 🔑".into()),
        ("SPECIAL", "p@ss=w0rd#with$chars'and\\\"quotes".into()),
        ("PUBLIC", "not-secret".into()),
    ];
    let want: Vec<(String, String)> = want.into_iter().map(|(k, v)| (k.into(), v)).collect();
    assert_eq!(got, want);
}

#[tokio::test]
async fn v7_fixture_mac_still_catches_injected_entry() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v7");
    let original = std::fs::read_to_string(dir.join("compat.sec")).unwrap();
    // Plaintext *values* are deliberately outside the MAC (see crypto::mac);
    // an injected entry is not — that's the attack the MAC exists for.
    let tampered = original.replace(
        "PUBLIC=not-secret",
        "PUBLIC=not-secret\nEXFIL_URL=https://attacker.example",
    );
    assert_ne!(original, tampered);

    let tmp = tempfile::tempdir().unwrap();
    let sec = tmp.path().join("compat.sec");
    std::fs::write(&sec, tampered).unwrap();
    let engine = EncryptionEngine::Local(LocalEncryptionOptions {
        key_file: Some(dir.join("compat.sec.key").to_string_lossy().to_string()),
    });

    let err = decrypt_sec_to_lines(
        &sec.to_string_lossy(),
        &engine,
        &crypto::mac::empty_schema_hash(),
    )
    .await
    .expect_err("an injected entry must fail the file MAC");
    assert!(err.to_string().to_lowercase().contains("mac"), "got: {err}");
}
