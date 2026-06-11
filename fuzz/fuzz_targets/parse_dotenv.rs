#![no_main]
//! Fuzzes the top-level `.sec` parser. This is the widest attack surface:
//! every byte here is attacker-controlled in dotsec's threat model (a
//! tampered file in a repo / PR). We only assert that parsing never panics
//! and never hangs — a malformed file must always be a clean `Err`, never a
//! crash.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser takes &str; non-UTF-8 is a legitimate early reject, not a
    // bug, so we just skip those inputs rather than lossy-converting (which
    // would hide UTF-8 boundary bugs in the grammar).
    if let Ok(s) = std::str::from_utf8(data) {
        // Must not panic. Ok or Err are both fine.
        let _ = dotenv::parse_dotenv(s);
    }
});
