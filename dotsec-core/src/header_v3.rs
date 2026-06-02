//! The dotsec file header: a single file-level directive carrying the
//! machine state (format tag, integrity tag, wrapped DEK).
//!
//! On disk:
//!
//! ```text
//! # @dotsec(format=v3, mac=base64-32-bytes, dek=base64-wrapped-dek)
//! ```
//!
//! Why this shape:
//! - Same `@directive` syntax as everything else in `.sec`. No second mini-grammar.
//! - Paren-grouped so the three fields visually belong together — "this whole
//!   parenthesised blob is the file's envelope, don't edit by hand."
//! - Distinct directive name (`@dotsec`) so the canonical bytes can trivially
//!   filter it out (the header can't include itself in its own integrity tag).
//!
//! Values are unquoted: base64 STANDARD only uses `A-Za-z0-9+/=`, none of
//! which clashes with the param separator (`,`) or the closing paren (`)`).
//!
//! Forward-compat: unknown param names are ignored on parse, so a future
//! `@dotsec(format=v3, mac=..., dek=..., kms-context=...)` round-trips
//! cleanly through older readers (they'd reject if they need to verify the
//! tag, since the canonical would differ — but they don't crash).

use base64::{engine::general_purpose::STANDARD, Engine as _};
use dotenv::Line;

/// Directive name used for the dotsec file header — match this on
/// `Line::Directive { name, .. }` to find or filter the header line.
pub const HEADER_DIRECTIVE_NAME: &str = "dotsec";

/// Wire-format tag carried as `format=v3`. Bumped only when the canonical
/// serialization or integrity-tag construction changes incompatibly.
pub const FORMAT_TAG_V3: &str = "v3";

#[derive(Clone, PartialEq, Eq)]
pub struct HeaderV3 {
    pub mac: [u8; 32],
    pub wrapped_dek: Vec<u8>,
}

/// Hand-rolled `Debug` that redacts `mac` and `wrapped_dek`. The wrapped DEK
/// is encrypted, but defense-in-depth: leaking it to logs / panic traces
/// undermines wrapping-key rotation later.
impl std::fmt::Debug for HeaderV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeaderV3")
            .field("mac", &"<32 bytes>")
            .field(
                "wrapped_dek",
                &format!("<{} bytes>", self.wrapped_dek.len()),
            )
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HeaderError {
    #[error("no @dotsec(...) directive found")]
    Missing,
    #[error("@dotsec(...) is missing required param: {0}")]
    MissingField(&'static str),
    #[error("@dotsec(...) param `{field}` is malformed: {reason}")]
    MalformedField {
        field: &'static str,
        reason: String,
    },
    #[error("unsupported wire-format `{0}` — this dotsec only understands `v3`")]
    UnsupportedFormat(String),
    #[error("@dotsec(...) field `{0}` appears more than once — refusing to pick one")]
    DuplicateField(&'static str),
}

impl HeaderV3 {
    /// Render as the inner body of `@dotsec(...)` — does NOT include the
    /// leading `@dotsec(` or trailing `)`. The dotenv renderer wraps the
    /// parens when it sees a `Line::Directive` named "dotsec".
    pub fn format_inner(&self) -> String {
        format!(
            "format={format}, mac={mac}, dek={dek}",
            format = FORMAT_TAG_V3,
            mac = STANDARD.encode(self.mac),
            dek = STANDARD.encode(&self.wrapped_dek),
        )
    }

    /// Build a `Line::Directive` carrying this header.
    pub fn to_directive_line(&self) -> Line {
        Line::Directive {
            name: HEADER_DIRECTIVE_NAME.to_string(),
            value: Some(self.format_inner()),
        }
    }

    /// Extract the header from a parsed file. Scans file-level directives
    /// (everything before the first Kv) for a `@dotsec(...)` and parses it.
    pub fn extract_from_lines(lines: &[Line]) -> Result<Self, HeaderError> {
        let inner = file_directives(lines)
            .into_iter()
            .find_map(|(name, value)| {
                if name == HEADER_DIRECTIVE_NAME {
                    value
                } else {
                    None
                }
            })
            .ok_or(HeaderError::Missing)?;
        Self::parse_inner(&inner)
    }

    /// Cheap predicate: does this set of lines contain a `@dotsec(...)`?
    pub fn is_present(lines: &[Line]) -> bool {
        file_directives(lines)
            .iter()
            .any(|(name, _)| name == HEADER_DIRECTIVE_NAME)
    }

    /// Parse just the inner `name=value, name=value` body. The
    /// `Line::Directive { name: "dotsec", value: Some(...) }` carries
    /// exactly this string.
    pub fn parse_inner(inner: &str) -> Result<Self, HeaderError> {
        let mut format: Option<String> = None;
        let mut mac_b64: Option<String> = None;
        let mut dek_b64: Option<String> = None;

        for raw in inner.split(',') {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            let Some((name, value)) = raw.split_once('=') else {
                continue;
            };
            let name = name.trim();
            let value = value.trim();
            match name {
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

        Ok(HeaderV3 { mac, wrapped_dek })
    }
}

/// Iterate file-level directives (everything before the first Kv) as
/// (name, value) pairs. Helper used by `extract_from_lines` + `is_present`
/// so the "scan top-of-file directives" logic isn't duplicated.
fn file_directives(lines: &[Line]) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    for line in lines {
        match line {
            Line::Kv { .. } => break,
            Line::Directive { name, value } => {
                out.push((name.clone(), value.clone()));
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use dotenv::lines_to_string;

    fn sample() -> HeaderV3 {
        HeaderV3 {
            mac: [0xAB; 32],
            wrapped_dek: vec![0x01, 0x02, 0x03, 0x04, 0x05],
        }
    }

    #[test]
    fn format_then_parse_inner_roundtrip() {
        let h = sample();
        let inner = h.format_inner();
        let parsed = HeaderV3::parse_inner(&inner).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn extract_from_a_parsed_file() {
        let h = sample();
        // Synthesize a file that contains the @dotsec(...) directive plus
        // other content, then re-parse via the dotenv parser to mimic the
        // real read path.
        let source = format!("# @{}({})\nFOO=bar\n", HEADER_DIRECTIVE_NAME, h.format_inner());
        let lines = dotenv::parse_dotenv(&source).unwrap();
        let extracted = HeaderV3::extract_from_lines(&lines).unwrap();
        assert_eq!(extracted, h);
    }

    #[test]
    fn round_trip_through_dotenv_parser() {
        let h = sample();
        let src = format!(
            "# @{}({})\nFOO=bar\n",
            HEADER_DIRECTIVE_NAME,
            h.format_inner()
        );
        let lines = dotenv::parse_dotenv(&src).unwrap();
        let rendered = lines_to_string(&lines);
        assert_eq!(rendered, src, "dotenv parse → render must preserve bytes");
    }

    #[test]
    fn header_directive_coexists_with_other_directives() {
        // Real files have @provider, @default-encrypt next to @dotsec.
        // The parser + renderer must keep them all on the same comment line
        // (or separate lines, depending on input) without losing any.
        let h = sample();
        let src = format!(
            "# @{}({}) @provider=local @default-encrypt\nFOO=bar\n",
            HEADER_DIRECTIVE_NAME,
            h.format_inner()
        );
        let lines = dotenv::parse_dotenv(&src).unwrap();
        let extracted = HeaderV3::extract_from_lines(&lines).unwrap();
        assert_eq!(extracted, h);
        // Provider still extractable too.
        let cfg = dotenv::extract_file_config(&lines);
        assert_eq!(cfg.provider.as_deref(), Some("local"));
        assert_eq!(cfg.default_encrypt, Some(true));
    }

    #[test]
    fn missing_directive_is_not_an_error_in_is_present() {
        let lines = dotenv::parse_dotenv("FOO=bar\n").unwrap();
        assert!(!HeaderV3::is_present(&lines));
        let err = HeaderV3::extract_from_lines(&lines).unwrap_err();
        assert!(matches!(err, HeaderError::Missing));
    }

    #[test]
    fn parse_rejects_unsupported_format() {
        let err = HeaderV3::parse_inner("format=v99, mac=AA==, dek=AQ==").unwrap_err();
        assert!(matches!(err, HeaderError::UnsupportedFormat(v) if v == "v99"));
    }

    #[test]
    fn parse_rejects_missing_required_fields() {
        // Missing format → "format" is what we check first.
        let err = HeaderV3::parse_inner("mac=AA==, dek=AQ==").unwrap_err();
        assert!(matches!(err, HeaderError::MissingField("format")));

        // Format present but no mac
        let err = HeaderV3::parse_inner("format=v3, dek=AQ==").unwrap_err();
        assert!(matches!(err, HeaderError::MissingField("mac")));

        // Format + mac but no dek
        let mac = STANDARD.encode([0u8; 32]);
        let err = HeaderV3::parse_inner(&format!("format=v3, mac={mac}")).unwrap_err();
        assert!(matches!(err, HeaderError::MissingField("dek")));
    }

    #[test]
    fn parse_rejects_malformed_mac_length() {
        let err =
            HeaderV3::parse_inner("format=v3, mac=AAAAAA==, dek=AQ==").unwrap_err();
        assert!(matches!(
            err,
            HeaderError::MalformedField { field: "mac", .. }
        ));
    }

    #[test]
    fn parse_rejects_empty_dek() {
        let mac = STANDARD.encode([0u8; 32]);
        let err = HeaderV3::parse_inner(&format!("format=v3, mac={mac}, dek=")).unwrap_err();
        assert!(matches!(
            err,
            HeaderError::MalformedField { field: "dek", .. }
        ));
    }

    #[test]
    fn parse_rejects_duplicate_mac() {
        let mac1 = STANDARD.encode([0u8; 32]);
        let mac2 = STANDARD.encode([1u8; 32]);
        let err =
            HeaderV3::parse_inner(&format!("format=v3, mac={mac1}, mac={mac2}, dek=AQ==")).unwrap_err();
        assert!(matches!(err, HeaderError::DuplicateField("mac")));
    }

    #[test]
    fn parse_rejects_duplicate_dek() {
        let mac = STANDARD.encode([0u8; 32]);
        let err =
            HeaderV3::parse_inner(&format!("format=v3, mac={mac}, dek=AQ==, dek=Ag==")).unwrap_err();
        assert!(matches!(err, HeaderError::DuplicateField("dek")));
    }

    #[test]
    fn parse_ignores_unknown_params_for_forward_compat() {
        let mac = STANDARD.encode([0u8; 32]);
        let h = HeaderV3::parse_inner(&format!(
            "format=v3, mac={mac}, dek=AQ==, kms-context=some-future-blob"
        ))
        .unwrap();
        assert_eq!(h.mac, [0u8; 32]);
        assert_eq!(h.wrapped_dek, vec![0x01]);
    }

    #[test]
    fn parse_accepts_kms_sized_wrapped_dek() {
        // AWS KMS GenerateDataKey returns ~184-byte wrapped DEK. Confirm that
        // round-trips through the directive format without truncation.
        let wrapped_dek: Vec<u8> = (0..184).map(|i| (i % 256) as u8).collect();
        let h = HeaderV3 {
            mac: [0xAB; 32],
            wrapped_dek: wrapped_dek.clone(),
        };
        let parsed = HeaderV3::parse_inner(&h.format_inner()).unwrap();
        assert_eq!(parsed.wrapped_dek, wrapped_dek);
        assert_eq!(parsed.wrapped_dek.len(), 184);
    }

    #[test]
    fn parse_accepts_oversized_wrapped_dek() {
        let wrapped_dek: Vec<u8> = (0..1024).map(|i| (i * 31 % 256) as u8).collect();
        let h = HeaderV3 {
            mac: [0; 32],
            wrapped_dek: wrapped_dek.clone(),
        };
        let parsed = HeaderV3::parse_inner(&h.format_inner()).unwrap();
        assert_eq!(parsed.wrapped_dek, wrapped_dek);
    }
}
