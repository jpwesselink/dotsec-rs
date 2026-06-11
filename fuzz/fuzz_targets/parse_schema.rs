#![no_main]
//! Fuzzes the schema-file parser. Separate entry point (Rule::schema) with
//! its own unwrap on line 620 (`schema_key` inner). Same invariant: no panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = dotenv::parse_schema(s);
    }
});
