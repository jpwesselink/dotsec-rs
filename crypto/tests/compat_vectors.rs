//! Format-compatibility vectors for the dotsec v3 crypto primitives.
//!
//! Every value below was produced by dotsec 7.x with aes-gcm 0.10, hmac 0.12,
//! sha2 0.10 and age 0.11. They pin the on-disk format: a dependency bump (or
//! any refactor) that changes one of these breaks existing `.sec` files.
//!
//! DO NOT regenerate these to make a failing test pass — a failure here means
//! existing users' files would stop decrypting or verifying.
//!
//! The age identity below is a throwaway test key, not a real secret.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use crypto::mac::{canonical_serialize, schema_hash, CanonicalEntry};

/// Fixed test DEK: bytes 0x00..=0x1f.
fn dek() -> Vec<u8> {
    (0u8..32).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn key_commitment_is_stable() {
    assert_eq!(
        hex(&crypto::compute_key_commitment(&dek())),
        "5266f2de1d6e532576cb3a15e4feafd4ce5698c3d2779fad7f8f35f2590e269c"
    );
}

#[test]
fn schema_hash_is_stable() {
    assert_eq!(
        hex(&schema_hash(Some(b"API_KEY\n# @encrypt\n"))),
        "c3e29ce5c36eb5ce678a23e34ef7ad3c868e0375c5c3dc2e653a189340d7b6c2"
    );
    assert_eq!(
        hex(&crypto::mac::empty_schema_hash()),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn canonical_form_and_file_mac_are_stable() {
    let entries = vec![
        CanonicalEntry {
            key: "A".into(),
            directives: vec![("encrypt".into(), None)],
            value: "ENC[xyz]".into(),
        },
        CanonicalEntry {
            key: "B".into(),
            directives: vec![("type".into(), Some("string".into()))],
            value: "plain".into(),
        },
    ];
    let canon = canonical_serialize(
        &[
            ("provider".into(), Some("local".into())),
            ("default-encrypt".into(), None),
        ],
        &entries,
        &schema_hash(Some(b"API_KEY\n# @encrypt\n")),
    );
    assert_eq!(STANDARD.encode(&canon), "ZG90c2VjLW1hYy12MwpzY2hlbWEtc2hhMjU2PWMzZTI5Y2U1YzM2ZWI1Y2U2NzhhMjNlMzRlZjdhZDNjODY4ZTAzNzVjNWMzZGMyZTY1M2ExODkzNDBkN2I2YzIKZmlsZS1kaXJlY3RpdmU6ZGVmYXVsdC1lbmNyeXB0PQpmaWxlLWRpcmVjdGl2ZTpwcm92aWRlcj1sb2NhbAplbnRyeTpBCiAgZGlyZWN0aXZlOmVuY3J5cHQ9CiAgZW5jOkVOQ1t4eXpdCmVudHJ5OkIK");

    let mac = crypto::compute_file_mac(&dek(), &canon);
    assert_eq!(
        hex(&mac),
        "2a63708a9984e75ee5f5d628422ba7f4997ff8b620ace95dfa2dcd518c46910d"
    );
    crypto::verify_file_mac(&dek(), &canon, &mac).unwrap();
}

#[test]
fn existing_enc_values_still_decrypt() {
    let vectors: [(&str, &str, &str); 4] = [
        ("EMPTY", "", "ENC[Umby3h1uUyV2yzoV5P6v1M5WmMPSd5+tf4818lkOJpxpIKlT+6GNhDVxVI5j28pwBNe0u/8FSvmbJ78ZSh1tL8yLoBb6CZVXyAvgWYUco1v1SYW16WUJl9qqgAoj5GFRtQkZoxUC/tYSb/JNoIloamm4PRDj7BonE0Ltt6U/vOmwb5QAknO1YyhL++fJ9OqnbxAWaWHvXFXW5sBD9V0dh3YHUPf9x7FBKwo7wvLr3sDun+qogDqMnCgoBxc=]"),
        ("SHORT", "x", "ENC[Umby3h1uUyV2yzoV5P6v1M5WmMPSd5+tf4818lkOJpx4dE7UtNqQxkg9hv5Wp+y3HoMzSp1mbtotEsjwPaF9Ou/LzlrMMgUehuzhF2+/qyTeoie/4LU7mOPSSXR/osocmRRlbHRs7mJpMHCMfBUHK9IUcMJpCLS7G0TvWVAlEIDcYSnJc+kw2Zvks4K5FdoN48FTcl1Q+ZHAMInM/c8G9diQt8+5mDqleD4yYqIwGyCbL3OcqOeyt+v236g=]"),
        ("PAD62", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ENC[Umby3h1uUyV2yzoV5P6v1M5WmMPSd5+tf4818lkOJpy74OuvgL0A5hjUJIrWuc9qhgF5V8gWIwf0wa4tf5awdr/pxZy0mkHi8JoByNHVl4mKR0iKFcpzJZIHzHqNRT7R39EhXuxJ1rE8Sdk0UAnM00tMpHDinJZ9WWBtTdb7lo7TL0ijTm43vI/uZUZGOyS7kwKCjJTflw7PDQ6rRTgrIJr/+cBopKhOgA432sWtVYldoK1nJ0XVCJFQfP8=]"),
        ("UNICODE", "秘密 🔑", "ENC[Umby3h1uUyV2yzoV5P6v1M5WmMPSd5+tf4818lkOJpwrlc61Ic7eevMDFNN8yTZMw3wKdIvfaFNjeq8FDOwkeCEd9vdzjEHrCldnnDCuxDGexnaijOBm4r+gnPpKfIFTKRNZfA3XOxCshSLe4uD1KWaN7b3YzagFxKfNnw==]"),
    ];
    for (aad, plaintext, enc) in vectors {
        assert_eq!(
            crypto::decrypt_value(enc, &dek(), aad).unwrap(),
            plaintext,
            "aad={aad}"
        );
        // AAD binds the value to its key: the wrong key name must fail.
        assert!(crypto::decrypt_value(enc, &dek(), "OTHER").is_err());
    }
}

#[test]
fn existing_age_wrapped_dek_still_unwraps() {
    let identity = "AGE-SECRET-KEY-15FA436EU35ZPFJ5P453TGF0CAPG2L9NWG6WDF56P2TNX0EDT49DQZSRYEP";
    assert_eq!(
        crypto::local::recipient_from_identity(identity).unwrap(),
        "age12nj0vtnrn4clj40ek7avfj29mz47hh796r6yuxvuxutdpxtpdu4sq5drvp"
    );
    let wrapped = STANDARD
        .decode("YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBRZ0g2VFlqdlJQMzB4cUQydmZtYUpUSFVaUHVzQy9GdHdzRk1KMy9tYzNvCnY5eXZ5L1ZwYUVsVWt0NkdRSDc0QnkxZEVSYmpBVmRqQ2ZIbUx2QjZEdGsKLT4gP1lqLWdyZWFzZSBJfj0iIChWcikqIHhJfE81fSQKRFFNeGJ2K1ZjVy9yMnAwRkNBemtWaXpGK0NuaDcvQURwVGM3OW9UQ0s0bDE5cDFEN2V5R1lFNC9ZV3l2TWcKLS0tIDYyY0ZqYlZ2L0wydnhOYnBicWNXWjRhenY0TmpKOG4xVVZHb2lOcHZaN0EKmVEIj2JF/Ajn6U+tjlzQB/TmMlpZWMOZYqVX6p/D+l9OTz4v4GletprccdMLrHaTE5NSMhgO7S67Y22pvJOHMQ==")
        .unwrap();
    let unwrapped = crypto::local::unwrap_dek(&wrapped, identity).unwrap();
    assert_eq!(unwrapped.as_slice(), dek().as_slice());
}
