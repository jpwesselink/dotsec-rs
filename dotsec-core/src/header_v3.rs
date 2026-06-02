//! V3 `#!dotsec` header line: a single self-describing line that replaces the
//! v2 `__DOTSEC_KEY__="..."` Kv pair.
//!
//! Wire format (one line, terminated by `\n`):
//!
//! ```text
//! #!dotsec version=6.0.0 format=v3 mac=<base64-32-bytes> dek=<base64-wrapped-dek>
//! ```
//!
//! - `version` — the dotsec build that wrote the file (no prerelease suffix —
//!   stable across PRs of the same line, like the existing header banner).
//! - `format` — wire-format tag; this module only emits/accepts `v3`.
//! - `mac`   — base64 STANDARD of the 32-byte HMAC produced by
//!   `crypto::compute_file_mac` over the canonical serialization.
//! - `dek`   — base64 STANDARD of the wrapped DEK (age-wrapped for local,
//!   KMS-wrapped for AWS — same on-disk bytes as v2).
//!
//! Why a `#!` shebang prefix: the dotenv parser sees the line as a regular
//! comment, so legacy code that ignores comments keeps working without grammar
//! changes. The `!` makes the prefix unique enough that we can confidently
//! distinguish it from user-authored comments.
//!
//! Token grammar:
//! - Tokens are space-separated.
//! - Each `name=value` token splits on the *first* `=` only; the value may
//!   contain trailing `=` padding from base64 STANDARD, which is what we want.
//! - Unknown tokens are ignored on parse (forward-compat).
//! - Repeated tokens: last write wins (forward-compat).

use base64::{engine::general_purpose::STANDARD, Engine as _};

pub const HEADER_PREFIX: &str = "#!dotsec";
pub const FORMAT_TAG_V3: &str = "v3";

#[derive(Clone, PartialEq, Eq)]
pub struct HeaderV3 {
    pub version: String,
    pub mac: [u8; 32],
    pub wrapped_dek: Vec<u8>,
}

/// Hand-rolled `Debug` that redacts `mac` and `wrapped_dek`. The wrapped DEK
/// is encrypted, but defense-in-depth: leaking it to logs / panic traces
/// undermines wrapping-key rotation later.
impl std::fmt::Debug for HeaderV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeaderV3")
            .field("version", &self.version)
            .field("mac", &"<32 bytes>")
            .field("wrapped_dek", &format!("<{} bytes>", self.wrapped_dek.len()))
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HeaderError {
    #[error("not a dotsec v3 header line")]
    NotV3Header,
    #[error("header is missing required field: {0}")]
    MissingField(&'static str),
    #[error("header field `{field}` is malformed: {reason}")]
    MalformedField {
        field: &'static str,
        reason: String,
    },
    #[error("unsupported wire-format `{0}` — this dotsec only understands `v3`")]
    UnsupportedFormat(String),
    /// A security-critical field (`mac` or `dek`) appeared more than once in
    /// the header. Last-write-wins on unknowns is forward-compat; on
    /// `mac`/`dek` it's a footgun (a forensic tool reading the file would
    /// disagree with the parser on which value is canonical).
    #[error("header field `{0}` appears more than once — refusing to pick one")]
    DuplicateField(&'static str),
}

impl HeaderV3 {
    /// Render the header as the single on-disk line, **without** trailing newline.
    /// Callers append the newline (or use `format_line`).
    pub fn format(&self) -> String {
        format!(
            "{prefix} version={version} format={format} mac={mac} dek={dek}",
            prefix = HEADER_PREFIX,
            version = self.version,
            format = FORMAT_TAG_V3,
            mac = STANDARD.encode(self.mac),
            dek = STANDARD.encode(&self.wrapped_dek),
        )
    }

    /// Render with a trailing newline — the usual write-to-file form.
    pub fn format_line(&self) -> String {
        let mut s = self.format();
        s.push('\n');
        s
    }

    /// Parse a single line. Strips an optional trailing `\r\n`/`\n`.
    /// Returns `Err(NotV3Header)` if the line doesn't start with `#!dotsec` —
    /// callers use that as the cheap "is this even a header?" check.
    pub fn parse(line: &str) -> Result<Self, HeaderError> {
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        let body = trimmed
            .strip_prefix(HEADER_PREFIX)
            .ok_or(HeaderError::NotV3Header)?;
        // Require whitespace immediately after the prefix so `#!dotsec-foo` doesn't match.
        if !body.starts_with(' ') && !body.starts_with('\t') {
            return Err(HeaderError::NotV3Header);
        }

        let mut version: Option<String> = None;
        let mut format: Option<String> = None;
        let mut mac_b64: Option<String> = None;
        let mut dek_b64: Option<String> = None;

        for token in body.split_whitespace() {
            // splitn(2, '=') keeps any trailing `=` padding inside the value.
            let mut parts = token.splitn(2, '=');
            let name = parts.next().unwrap_or("");
            let value = match parts.next() {
                Some(v) => v,
                None => continue, // bare token, skip
            };
            match name {
                "version" => version = Some(value.to_string()),
                "format" => format = Some(value.to_string()),
                "mac" => {
                    if mac_b64.is_some() {
                        return Err(HeaderError::DuplicateField("mac"));
                    }
                    mac_b64 = Some(value.to_string());
                }
                "dek" => {
                    if dek_b64.is_some() {
                        return Err(HeaderError::DuplicateField("dek"));
                    }
                    dek_b64 = Some(value.to_string());
                }
                _ => {} // forward-compat: ignore unknown fields
            }
        }

        let format = format.ok_or(HeaderError::MissingField("format"))?;
        if format != FORMAT_TAG_V3 {
            return Err(HeaderError::UnsupportedFormat(format));
        }
        let version = version.ok_or(HeaderError::MissingField("version"))?;
        let mac_b64 = mac_b64.ok_or(HeaderError::MissingField("mac"))?;
        let dek_b64 = dek_b64.ok_or(HeaderError::MissingField("dek"))?;

        let mac_bytes = STANDARD
            .decode(&mac_b64)
            .map_err(|e| HeaderError::MalformedField {
                field: "mac",
                reason: e.to_string(),
            })?;
        if mac_bytes.len() != 32 {
            return Err(HeaderError::MalformedField {
                field: "mac",
                reason: format!("expected 32 bytes, got {}", mac_bytes.len()),
            });
        }
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&mac_bytes);

        let wrapped_dek =
            STANDARD
                .decode(&dek_b64)
                .map_err(|e| HeaderError::MalformedField {
                    field: "dek",
                    reason: e.to_string(),
                })?;
        if wrapped_dek.is_empty() {
            return Err(HeaderError::MalformedField {
                field: "dek",
                reason: "wrapped DEK must not be empty".into(),
            });
        }

        Ok(HeaderV3 {
            version,
            mac,
            wrapped_dek,
        })
    }

    /// Cheap predicate: does `line` look like a v3 header line? Doesn't validate
    /// fields. Useful when scanning a parsed file to locate the header.
    pub fn is_header_line(line: &str) -> bool {
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        let Some(body) = trimmed.strip_prefix(HEADER_PREFIX) else {
            return false;
        };
        body.starts_with(' ') || body.starts_with('\t')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> HeaderV3 {
        HeaderV3 {
            version: "6.0.0".into(),
            mac: [0xAB; 32],
            wrapped_dek: vec![0x01, 0x02, 0x03, 0x04, 0x05],
        }
    }

    #[test]
    fn format_then_parse_roundtrip() {
        let h = sample();
        let line = h.format_line();
        let parsed = HeaderV3::parse(&line).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn format_line_ends_with_newline_format_does_not() {
        let h = sample();
        assert!(!h.format().ends_with('\n'));
        assert!(h.format_line().ends_with('\n'));
    }

    #[test]
    fn parse_strips_crlf() {
        let h = sample();
        let mut line = h.format();
        line.push_str("\r\n");
        let parsed = HeaderV3::parse(&line).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn parse_rejects_non_v3_lines() {
        assert!(matches!(
            HeaderV3::parse("# regular comment"),
            Err(HeaderError::NotV3Header)
        ));
        assert!(matches!(
            HeaderV3::parse("FOO=bar"),
            Err(HeaderError::NotV3Header)
        ));
        assert!(matches!(
            HeaderV3::parse(""),
            Err(HeaderError::NotV3Header)
        ));
    }

    #[test]
    fn parse_rejects_prefix_without_space() {
        // `#!dotsec-junk` shouldn't be treated as a header.
        assert!(matches!(
            HeaderV3::parse("#!dotsec-junk version=6.0.0 format=v3 mac=AA== dek=AQ=="),
            Err(HeaderError::NotV3Header)
        ));
    }

    #[test]
    fn parse_rejects_unsupported_format() {
        let line = "#!dotsec version=6.0.0 format=v99 mac=AA== dek=AQ==";
        let err = HeaderV3::parse(line).unwrap_err();
        assert!(matches!(err, HeaderError::UnsupportedFormat(v) if v == "v99"));
    }

    #[test]
    fn parse_rejects_missing_required_fields() {
        // Missing format entirely → MissingField("format") wins (checked first).
        let err = HeaderV3::parse("#!dotsec version=6.0.0 mac=AA== dek=AQ==").unwrap_err();
        assert!(matches!(err, HeaderError::MissingField("format")));

        // Has format=v3 but no version
        let err = HeaderV3::parse("#!dotsec format=v3 mac=AA== dek=AQ==").unwrap_err();
        assert!(matches!(err, HeaderError::MissingField("version")));

        // Has format+version but no mac
        let err = HeaderV3::parse("#!dotsec version=6.0.0 format=v3 dek=AQ==").unwrap_err();
        assert!(matches!(err, HeaderError::MissingField("mac")));

        // Has everything except dek
        let mac = STANDARD.encode([0u8; 32]);
        let line = format!("#!dotsec version=6.0.0 format=v3 mac={mac}");
        let err = HeaderV3::parse(&line).unwrap_err();
        assert!(matches!(err, HeaderError::MissingField("dek")));
    }

    #[test]
    fn parse_rejects_malformed_mac_length() {
        // Valid base64 of 4 bytes — but not 32 bytes after decode.
        let line = "#!dotsec version=6.0.0 format=v3 mac=AAAAAA== dek=AQ==";
        let err = HeaderV3::parse(line).unwrap_err();
        assert!(matches!(
            err,
            HeaderError::MalformedField { field: "mac", .. }
        ));
    }

    #[test]
    fn parse_rejects_empty_dek() {
        let mac = STANDARD.encode([0u8; 32]);
        let line = format!("#!dotsec version=6.0.0 format=v3 mac={mac} dek=");
        let err = HeaderV3::parse(&line).unwrap_err();
        assert!(matches!(
            err,
            HeaderError::MalformedField { field: "dek", .. }
        ));
    }

    #[test]
    fn parse_ignores_unknown_fields_forward_compat() {
        let mac = STANDARD.encode([0u8; 32]);
        let line = format!(
            "#!dotsec version=6.0.0 format=v3 mac={mac} dek=AQ== future-field=ignored-by-old-readers"
        );
        let parsed = HeaderV3::parse(&line).unwrap();
        assert_eq!(parsed.version, "6.0.0");
    }

    #[test]
    fn parse_last_token_wins_for_duplicate_version() {
        // Forward-compat for benign fields: a future writer might emit `version` twice.
        let mac = STANDARD.encode([0u8; 32]);
        let line = format!(
            "#!dotsec version=5.9.9 version=6.0.0 format=v3 mac={mac} dek=AQ=="
        );
        let parsed = HeaderV3::parse(&line).unwrap();
        assert_eq!(parsed.version, "6.0.0");
    }

    #[test]
    fn parse_rejects_duplicate_mac_token() {
        // Security-critical: forensic tooling and the parser must agree on
        // which MAC is canonical. Refuse the file rather than guess.
        let mac1 = STANDARD.encode([0u8; 32]);
        let mac2 = STANDARD.encode([1u8; 32]);
        let line = format!("#!dotsec version=6.0.0 format=v3 mac={mac1} mac={mac2} dek=AQ==");
        let err = HeaderV3::parse(&line).unwrap_err();
        assert!(matches!(err, HeaderError::DuplicateField("mac")));
    }

    #[test]
    fn parse_rejects_duplicate_dek_token() {
        let mac = STANDARD.encode([0u8; 32]);
        let line = format!("#!dotsec version=6.0.0 format=v3 mac={mac} dek=AQ== dek=Ag==");
        let err = HeaderV3::parse(&line).unwrap_err();
        assert!(matches!(err, HeaderError::DuplicateField("dek")));
    }

    #[test]
    fn is_header_line_predicate() {
        assert!(HeaderV3::is_header_line("#!dotsec version=6.0.0"));
        assert!(HeaderV3::is_header_line("#!dotsec\tversion=6.0.0"));
        assert!(HeaderV3::is_header_line("#!dotsec version=6.0.0\n"));
        assert!(!HeaderV3::is_header_line("#!dotsec-junk"));
        assert!(!HeaderV3::is_header_line("# dotsec v6.0.0"));
        assert!(!HeaderV3::is_header_line(""));
    }

    #[test]
    fn parse_accepts_kms_sized_wrapped_dek() {
        // AWS KMS `GenerateDataKey` returns a wrapped DEK around 184 bytes
        // (varies with key type). The v3 header format must round-trip those
        // verbatim. This test fills a 184-byte wrapped DEK with deterministic
        // bytes, formats, parses, and checks the round-trip. Acts as a
        // smoke-coverage substitute for the missing end-to-end AWS test.
        let wrapped_dek: Vec<u8> = (0..184).map(|i| (i % 256) as u8).collect();
        let header = HeaderV3 {
            version: "6.0.0".into(),
            mac: [0xAB; 32],
            wrapped_dek: wrapped_dek.clone(),
        };
        let parsed = HeaderV3::parse(&header.format_line()).expect("parse round-trip");
        assert_eq!(parsed.wrapped_dek, wrapped_dek);
        assert_eq!(parsed.wrapped_dek.len(), 184);
    }

    #[test]
    fn parse_accepts_oversized_wrapped_dek() {
        // Future KMS key types may produce larger wrapped DEKs. The format
        // imposes no upper bound — verify a 1 KiB DEK still round-trips.
        let wrapped_dek: Vec<u8> = (0..1024).map(|i| (i * 31 % 256) as u8).collect();
        let header = HeaderV3 {
            version: "6.0.0".into(),
            mac: [0; 32],
            wrapped_dek: wrapped_dek.clone(),
        };
        let parsed = HeaderV3::parse(&header.format_line()).expect("parse round-trip");
        assert_eq!(parsed.wrapped_dek, wrapped_dek);
    }

    #[test]
    fn format_contains_base64_padding_safely() {
        // 32-byte MAC base64 STANDARD-encodes to 44 chars ending in `=`.
        // Make sure the trailing `=` survives format/parse round-trip via splitn(2).
        let h = HeaderV3 {
            version: "6.0.0".into(),
            mac: [0u8; 32],
            wrapped_dek: vec![0x01], // 1 byte → base64 "AQ==" (two `=` pads)
        };
        let parsed = HeaderV3::parse(&h.format_line()).unwrap();
        assert_eq!(parsed.mac, [0u8; 32]);
        assert_eq!(parsed.wrapped_dek, vec![0x01]);
    }
}
