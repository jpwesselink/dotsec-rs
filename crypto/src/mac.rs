//! Canonical serialization for the v3 file-level MAC.
//!
//! The MAC covers what an attacker could weaponize invisibly:
//!
//! - For every entry (encrypted or plaintext): the **entry name**. An attacker
//!   can't inject a new `EXFIL_URL=https://attacker.example` line and have it
//!   silently picked up.
//! - For **encrypted** entries: all directives plus the `ENC[…]` ciphertext
//!   bytes. Tampering with `@push`/`@key-id`/`@type`/etc. on encrypted entries
//!   trips the MAC; rollback of `ENC[…]` to a stale ciphertext under the same
//!   key name trips the MAC.
//! - The schema's canonical semantic form (via `schema_hash`).
//!
//! The MAC explicitly does **NOT** cover:
//!
//! - Plaintext **values**. Editing `PORT=3000` → `PORT=4000` is a dev-loop
//!   operation, not a tampering event.
//! - Inline directives on **plaintext** entries. If a plaintext entry has
//!   `@type=enum(...)` and an attacker flips it to `@type=string`, the MAC
//!   won't catch it. **Move plaintext validation rules into `dotsec.schema`**
//!   — schema directives ARE bound via `schema_hash`, and `dotsec validate`
//!   enforces them on every load.
//! - Comments, whitespace, blank lines. Reformatting is safe.
//!
//! Net trade-off: the integrity layer for plaintext-value *content* is the
//! schema, not the MAC. The MAC defends the file's *structure* — what entries
//! exist, what they're marked as, and what's in their ciphertext when they're
//! encrypted.
//!
//! `canonical_serialize` is pure (no I/O, no randomness). The same inputs
//! always produce the same bytes; rewriting whitespace / comments / plaintext
//! values must not change the result, so we sort per-entry directives by name
//! and emit no directives or value for entries whose value isn't `ENC[…]`
//! (their entry name is still emitted, so injection / rename / reorder still
//! trip the MAC).
//!
//! See `docs/superpowers/plans/2026-05-13-v3-format-mac-and-header.md` for the
//! full design rationale; its preamble documents the refinements that
//! produced the current scope (drop plaintext values from MAC, canonicalize
//! schema hash, promote `dotsec encrypt` from deferred to required).
//!
//! ## Wire format
//!
//! ```text
//! dotsec-mac-v3\n
//! schema-sha256=<hex(32 bytes)>\n
//! file-directive:<name>=<value>\n   (sorted by name; value empty when flag-only)
//! file-directive:<name>=<value>\n
//! entry:<key>\n                     (every entry, encrypted AND plaintext, in file order)
//!   directive:<name>=<value>\n      (encrypted entries only; sorted by name)
//!   directive:<name>=<value>\n
//!   enc:<literal-value>\n           (encrypted entries only)
//! entry:<key>\n                     (a plaintext entry — name only, no directives, no value)
//! entry:<key>\n
//!   …
//! ```
//! `crypto::is_encrypted_value` is the predicate — value must start with
//! `ENC[` AND end with `]`. An unterminated `ENC[abc` is treated as plaintext.

/// Domain-separation tag for v3 file MACs. Prevents accidental MAC reuse if a
/// future format introduces a different canonical form under the same DEK.
pub const DOMAIN_TAG: &[u8] = b"dotsec-mac-v3\n";

/// One entry's view as the MAC sees it. Owned types so callers don't have to
/// fight lifetimes against transient parses.
#[derive(Debug, Clone)]
pub struct CanonicalEntry {
    pub key: String,
    pub directives: Vec<(String, Option<String>)>,
    /// The literal on-disk value — `ENC[...]` for encrypted entries,
    /// plaintext otherwise. The canonicalizer picks the `enc:` vs `plain:`
    /// prefix based on the `ENC[` prefix.
    pub value: String,
}

/// Produce the canonical bytes that `compute_file_mac` will MAC under the DEK.
///
/// Inputs:
/// - `file_directives`: file-level directives (`@provider`, `@key-id`,
///   `@region`, `@default-encrypt`, …). Order doesn't matter — they're sorted
///   by name during serialization for determinism.
/// - `entries`: every key=value entry in the file, **in file order**. Order
///   matters here — the MAC covers ordering so `dotsec format` (which
///   re-orders) must re-MAC.
/// - `schema_hash`: SHA-256 of the active `dotsec.schema` content, or the
///   hash of empty bytes when no schema is present. Going through AAD ties
///   every file MAC to the schema state at MAC-time.
pub fn canonical_serialize(
    file_directives: &[(String, Option<String>)],
    entries: &[CanonicalEntry],
    schema_hash: &[u8; 32],
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(DOMAIN_TAG);

    out.extend_from_slice(b"schema-sha256=");
    out.extend_from_slice(hex(schema_hash).as_bytes());
    out.push(b'\n');

    // File-level directives sorted by name. Sort is stable so identical
    // (name, value) pairs preserve their relative order, which we then
    // serialize deterministically.
    let mut sorted_file_directives: Vec<&(String, Option<String>)> =
        file_directives.iter().collect();
    sorted_file_directives.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in &sorted_file_directives {
        out.extend_from_slice(b"file-directive:");
        out.extend_from_slice(name.as_bytes());
        out.push(b'=');
        if let Some(v) = value {
            out.extend_from_slice(v.as_bytes());
        }
        out.push(b'\n');
    }

    for entry in entries {
        // Every entry — encrypted OR plaintext — gets a name line. This is
        // what catches plaintext injection: an attacker who adds
        // `EXFIL_URL=...` shifts the canonical bytes and trips the MAC.
        out.extend_from_slice(b"entry:");
        out.extend_from_slice(entry.key.as_bytes());
        out.push(b'\n');

        // Plaintext entries contribute ONLY their name. Inline directives and
        // values are out of scope: editing `PORT=3000` → `PORT=4000` or
        // `@type=number` → `@type=string` on a plaintext entry must not trip
        // the MAC (dev-loop UX). Integrity for plaintext value *content*
        // belongs in `dotsec.schema`, which is bound to the MAC via
        // `schema_hash`. See module docs for the trade-off.
        //
        // Predicate is `crypto::is_encrypted_value` (not bare `starts_with`)
        // so that an unterminated `ENC[abc` value — half-edited, truncated,
        // or otherwise malformed — gets the conservative "treat as plaintext"
        // treatment that matches every other code site.
        if !crate::is_encrypted_value(&entry.value) {
            continue;
        }

        let mut sorted_directives: Vec<&(String, Option<String>)> =
            entry.directives.iter().collect();
        sorted_directives.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, value) in &sorted_directives {
            out.extend_from_slice(b"  directive:");
            out.extend_from_slice(name.as_bytes());
            out.push(b'=');
            if let Some(v) = value {
                out.extend_from_slice(v.as_bytes());
            }
            out.push(b'\n');
        }

        // ENC[…] ciphertext bytes are emitted so that:
        //   1. Rollback attacks (swap in older ENC[…] under same key) trip the MAC.
        //   2. Tampering with ciphertext bytes trips earlier than per-value AEAD.
        out.extend_from_slice(b"  enc:");
        out.extend_from_slice(entry.value.as_bytes());
        out.push(b'\n');
    }

    out
}

/// SHA-256 over input bytes — the value bound into every v3 file MAC via
/// `canonical_serialize`. Callers pass the schema's *canonical* form (see
/// `dotenv::schema_to_canonical_bytes`), not raw file bytes, so cosmetic
/// edits like `@description` or directive reordering don't invalidate
/// downstream MACs — only semantic schema changes do.
///
/// `None` returns the hash of empty input — a stable sentinel for "no schema
/// applied," so a file that's never had a schema still gets a deterministic
/// MAC input.
pub fn schema_hash(content: Option<&[u8]>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    if let Some(bytes) = content {
        hasher.update(bytes);
    }
    hasher.finalize().into()
}

/// The sentinel hash used when no schema is in effect — exactly equivalent to
/// `schema_hash(None)`. Exposed as a separate function so the "no schema"
/// case is searchable in code and unambiguous in tests.
pub fn empty_schema_hash() -> [u8; 32] {
    schema_hash(None)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key: &str, directives: &[(&str, Option<&str>)], value: &str) -> CanonicalEntry {
        CanonicalEntry {
            key: key.into(),
            directives: directives
                .iter()
                .map(|(n, v)| (n.to_string(), v.map(|s| s.to_string())))
                .collect(),
            value: value.into(),
        }
    }

    #[test]
    fn canonical_serialize_basic_shape() {
        let bytes = canonical_serialize(
            &[("provider".into(), Some("local".into()))],
            &[entry("FOO", &[("encrypt", None)], "ENC[abcd]")],
            &[0u8; 32],
        );
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("dotsec-mac-v3\n"));
        assert!(s.contains("schema-sha256=0000000000000000000000000000000000000000000000000000000000000000\n"));
        assert!(s.contains("file-directive:provider=local\n"));
        assert!(s.contains("entry:FOO\n"));
        assert!(s.contains("  directive:encrypt=\n"));
        assert!(s.contains("  enc:ENC[abcd]\n"));
    }

    #[test]
    fn plaintext_entry_name_in_canonical_but_value_and_directives_excluded() {
        // Plaintext entries contribute their NAME only — not inline
        // directives, not the value. The name is what catches injection;
        // the omissions preserve the dev-loop UX (edit values + inline
        // directives freely).
        let bytes = canonical_serialize(
            &[],
            &[entry("PORT", &[("type", Some("number"))], "3000")],
            &[0u8; 32],
        );
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("entry:PORT\n"), "plaintext entry name must be covered");
        assert!(!s.contains("3000"), "plaintext value must NOT be covered");
        assert!(
            !s.contains("directive:type"),
            "inline directives on plaintext entries must NOT be covered"
        );
        assert!(!s.contains("  plain:"));
        assert!(!s.contains("  enc:"));
    }

    #[test]
    fn plaintext_value_change_preserves_mac() {
        // Hand-editing PORT=3000 → PORT=4000 must not invalidate the MAC.
        let a = canonical_serialize(
            &[],
            &[entry("PORT", &[], "3000")],
            &[0u8; 32],
        );
        let b = canonical_serialize(
            &[],
            &[entry("PORT", &[], "4000")],
            &[0u8; 32],
        );
        assert_eq!(a, b);
    }

    #[test]
    fn plaintext_inline_directive_change_preserves_mac() {
        // Edge of the trade: inline directive flips on plaintext entries
        // don't trip the MAC. Move @type/@pattern into `dotsec.schema` (whose
        // canonical form IS bound via schema_hash) when the constraint must
        // be integrity-protected.
        let a = canonical_serialize(
            &[],
            &[entry("PORT", &[("type", Some("number"))], "3000")],
            &[0u8; 32],
        );
        let b = canonical_serialize(
            &[],
            &[entry("PORT", &[("type", Some("string"))], "3000")],
            &[0u8; 32],
        );
        assert_eq!(a, b);
    }

    #[test]
    fn reordering_plaintext_entries_invalidates_mac() {
        // Path-2 promise: plaintext entry names are in canonical, file order
        // matters → swapping two plaintext entries trips the MAC.
        let a = canonical_serialize(
            &[],
            &[entry("ALPHA", &[], "a"), entry("BETA", &[], "b")],
            &[0u8; 32],
        );
        let b = canonical_serialize(
            &[],
            &[entry("BETA", &[], "b"), entry("ALPHA", &[], "a")],
            &[0u8; 32],
        );
        assert_ne!(a, b);
    }

    #[test]
    fn renaming_plaintext_entry_invalidates_mac() {
        // An attacker who renames `LOG_LEVEL` → `DEBUG` to repurpose how the
        // app reads it gets caught even when the value doesn't change.
        let a = canonical_serialize(
            &[],
            &[entry("LOG_LEVEL", &[], "info")],
            &[0u8; 32],
        );
        let b = canonical_serialize(
            &[],
            &[entry("DEBUG", &[], "info")],
            &[0u8; 32],
        );
        assert_ne!(a, b);
    }

    #[test]
    fn removing_plaintext_entry_invalidates_mac() {
        // Dropping a plaintext entry (e.g. an attacker silently removes a
        // FEATURE_FLAG to change app behavior) trips the MAC.
        let a = canonical_serialize(
            &[],
            &[
                entry("FEATURE_FLAG", &[], "true"),
                entry("PORT", &[], "3000"),
            ],
            &[0u8; 32],
        );
        let b = canonical_serialize(&[], &[entry("PORT", &[], "3000")], &[0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn adding_plaintext_entry_invalidates_mac() {
        // Inject-protection: an attacker writing `EXFIL_URL=https://...`
        // into the .sec file shifts the canonical (new entry name appears)
        // and trips the MAC. Same applies to a legitimate hand-edit; users
        // who want to add entries by hand must run `dotsec encrypt` (or just
        // use `dotsec set --plaintext`, which re-MACs automatically).
        let a = canonical_serialize(
            &[],
            &[entry("PORT", &[], "3000")],
            &[0u8; 32],
        );
        let b = canonical_serialize(
            &[],
            &[
                entry("PORT", &[], "3000"),
                entry("EXFIL_URL", &[], "https://attacker.example"),
            ],
            &[0u8; 32],
        );
        assert_ne!(a, b);
    }

    #[test]
    fn adding_encrypted_entry_invalidates_mac() {
        // Encrypted-entry add is caught for both the name and the directives/value.
        let a = canonical_serialize(
            &[],
            &[entry("EXISTING", &[("encrypt", None)], "ENC[aaaa]")],
            &[0u8; 32],
        );
        let b = canonical_serialize(
            &[],
            &[
                entry("EXISTING", &[("encrypt", None)], "ENC[aaaa]"),
                entry("INJECTED", &[("encrypt", None)], "ENC[bbbb]"),
            ],
            &[0u8; 32],
        );
        assert_ne!(a, b);
    }

    #[test]
    fn duplicate_keys_produce_two_canonical_lines() {
        // `dotenv::parse_dotenv` accepts duplicate keys silently; making sure
        // we don't regress to dedupe (which would silently invalidate every
        // MAC for files with accidental duplicates). If we ever DO add
        // dedupe, this test fires and the change is intentional.
        let bytes = canonical_serialize(
            &[],
            &[
                entry("FOO", &[], "a"),
                entry("FOO", &[], "b"),
            ],
            &[0u8; 32],
        );
        let s = std::str::from_utf8(&bytes).unwrap();
        let first = s.find("entry:FOO\n").expect("first occurrence");
        let second = s[first + 1..].find("entry:FOO\n").expect("second occurrence");
        let _ = second;
        // Both entries appear → two distinct canonical lines.
        assert_eq!(s.matches("entry:FOO\n").count(), 2);
    }

    #[test]
    fn unterminated_enc_value_treated_as_plaintext() {
        // Predicate consistency (H2 from review): `is_encrypted_value`
        // requires both `ENC[` prefix and `]` suffix. An unterminated
        // `ENC[abc` is plaintext — the canonicalizer drops its directives
        // and value, same as any other plaintext entry.
        let bytes = canonical_serialize(
            &[],
            &[entry("FOO", &[("encrypt", None)], "ENC[truncated")],
            &[0u8; 32],
        );
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("entry:FOO\n"), "entry name still in canonical");
        assert!(
            !s.contains("ENC[truncated"),
            "malformed ENC value must not be emitted as encrypted"
        );
        assert!(
            !s.contains("directive:encrypt"),
            "directives on plaintext-fallthrough entries are excluded"
        );
    }

    #[test]
    fn encrypted_value_still_in_canonical() {
        // Rollback protection: changing the ENC[…] bytes (e.g. swapping in an older
        // ciphertext under the same key) MUST flip the canonical bytes.
        let a = canonical_serialize(
            &[],
            &[entry("DB", &[("encrypt", None)], "ENC[old-ciphertext]")],
            &[0u8; 32],
        );
        let b = canonical_serialize(
            &[],
            &[entry("DB", &[("encrypt", None)], "ENC[new-ciphertext]")],
            &[0u8; 32],
        );
        assert_ne!(a, b);
        // Sanity-check the literal is in there.
        let s_b = std::str::from_utf8(&b).unwrap();
        assert!(s_b.contains("  enc:ENC[new-ciphertext]\n"));
    }

    #[test]
    fn file_directives_sorted_by_name() {
        // Input order: region, provider, key-id. Output must be alphabetical.
        let bytes = canonical_serialize(
            &[
                ("region".into(), Some("us-east-1".into())),
                ("provider".into(), Some("aws".into())),
                ("key-id".into(), Some("alias/dotsec".into())),
            ],
            &[],
            &[0u8; 32],
        );
        let s = std::str::from_utf8(&bytes).unwrap();
        let key_id_pos = s.find("file-directive:key-id=").unwrap();
        let provider_pos = s.find("file-directive:provider=").unwrap();
        let region_pos = s.find("file-directive:region=").unwrap();
        assert!(key_id_pos < provider_pos);
        assert!(provider_pos < region_pos);
    }

    #[test]
    fn entry_directives_sorted_per_entry() {
        let bytes = canonical_serialize(
            &[],
            &[entry(
                "DB",
                &[
                    ("type", Some("string")),
                    ("encrypt", None),
                    ("push", Some("aws-ssm")),
                ],
                "ENC[x]",
            )],
            &[0u8; 32],
        );
        let s = std::str::from_utf8(&bytes).unwrap();
        let encrypt_pos = s.find("  directive:encrypt=").unwrap();
        let push_pos = s.find("  directive:push=").unwrap();
        let type_pos = s.find("  directive:type=").unwrap();
        assert!(encrypt_pos < push_pos);
        assert!(push_pos < type_pos);
    }

    #[test]
    fn entries_keep_file_order() {
        // First entry stays first even though its key sorts after the second.
        // (Only ENC[…] entries are in the canonical at all, so use those.)
        let bytes = canonical_serialize(
            &[],
            &[
                entry("ZEBRA", &[("encrypt", None)], "ENC[z]"),
                entry("APPLE", &[("encrypt", None)], "ENC[a]"),
            ],
            &[0u8; 32],
        );
        let s = std::str::from_utf8(&bytes).unwrap();
        let zebra_pos = s.find("entry:ZEBRA").unwrap();
        let apple_pos = s.find("entry:APPLE").unwrap();
        assert!(zebra_pos < apple_pos);
    }

    #[test]
    fn flag_directives_serialize_with_empty_value() {
        let bytes = canonical_serialize(
            &[("default-encrypt".into(), None)],
            &[],
            &[0u8; 32],
        );
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("file-directive:default-encrypt=\n"));
    }

    #[test]
    fn schema_hash_appears_as_lowercase_hex() {
        let mut schema_hash = [0u8; 32];
        schema_hash[0] = 0xab;
        schema_hash[31] = 0xcd;
        let bytes = canonical_serialize(&[], &[], &schema_hash);
        let s = std::str::from_utf8(&bytes).unwrap();
        // 32 bytes = 64 hex chars: ab + 30×00 + cd
        assert!(
            s.contains("schema-sha256=ab000000000000000000000000000000000000000000000000000000000000cd\n"),
            "got: {s}"
        );
    }

    #[test]
    fn deterministic_repeat_runs() {
        let inputs = || {
            (
                vec![("provider".to_string(), Some("local".to_string()))],
                vec![entry("X", &[("encrypt", None)], "ENC[abc]")],
            )
        };
        let (fd1, e1) = inputs();
        let (fd2, e2) = inputs();
        let a = canonical_serialize(&fd1, &e1, &[0u8; 32]);
        let b = canonical_serialize(&fd2, &e2, &[0u8; 32]);
        assert_eq!(a, b);
    }

    #[test]
    fn schema_hash_none_is_sha256_of_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = schema_hash(None);
        assert_eq!(
            hex(&hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn schema_hash_distinguishes_content() {
        let a = schema_hash(Some(b"# @encrypt\nDB_URL\n"));
        let b = schema_hash(Some(b"# @encrypt\nDB_URL"));
        let c = schema_hash(Some(b"# @encrypt\nAPI_KEY\n"));
        // Trailing newline matters (raw-bytes hash).
        assert_ne!(a, b);
        // Different keys obviously hash differently.
        assert_ne!(a, c);
    }

    #[test]
    fn schema_hash_empty_bytes_matches_none() {
        // Empty Some(&[]) and None both hash to SHA-256("") — the sentinel is stable.
        assert_eq!(schema_hash(None), schema_hash(Some(b"")));
    }

    #[test]
    fn schema_hash_deterministic() {
        let bytes = b"# @type=string\nFOO\n";
        assert_eq!(schema_hash(Some(bytes)), schema_hash(Some(bytes)));
    }

    #[test]
    fn input_directive_order_does_not_affect_output() {
        let a = canonical_serialize(
            &[
                ("region".into(), Some("us-east-1".into())),
                ("provider".into(), Some("aws".into())),
            ],
            &[],
            &[0u8; 32],
        );
        let b = canonical_serialize(
            &[
                ("provider".into(), Some("aws".into())),
                ("region".into(), Some("us-east-1".into())),
            ],
            &[],
            &[0u8; 32],
        );
        assert_eq!(a, b);
    }
}
