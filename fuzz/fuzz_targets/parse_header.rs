#![no_main]
//! Fuzzes `HeaderV3::parse_inner` directly — the most security-sensitive
//! parse step, since it decodes the wrapped DEK and the file MAC from
//! attacker-controlled base64. We feed the raw inner body (what sits between
//! `@dotsec(` and `)`) so the fuzzer doesn't waste cycles getting through the
//! outer grammar first.
//!
//! Invariant: parse_inner is total — every input yields Ok or a typed
//! HeaderError, never a panic, and the base64 decode of an oversized `dek=`
//! must not OOM (see the length-check follow-up in the review).
use libfuzzer_sys::fuzz_target;
use dotsec_core::header_v3::HeaderV3;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = HeaderV3::parse_inner(s);
    }
});
