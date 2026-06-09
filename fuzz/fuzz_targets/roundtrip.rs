#![no_main]
//! Round-trip / idempotency fuzzer. This is the one that catches the subtle
//! class — not crashes but *silent corruption*. If a file parses, we render
//! it back to text and re-parse. The two parses must produce identical line
//! structures. A mismatch means render+parse isn't a faithful inverse, which
//! is exactly how a value like a literal `${FOO` (unclosed) or an edge-case
//! quote could mutate across an encrypt→decrypt→write cycle.
//!
//! Note: we compare the *second* and *third* parse, not first vs second.
//! The first render may legitimately normalize whitespace; what must be
//! stable is the fixed point. parse(render(parse(render(x)))) == parse(render(x)).
use libfuzzer_sys::fuzz_target;
use dotenv::{parse_dotenv, lines_to_string};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };

    let Ok(lines1) = parse_dotenv(s) else { return };
    let rendered1 = lines_to_string(&lines1);

    let Ok(lines2) = parse_dotenv(&rendered1) else {
        // Rendering produced something that no longer parses — that's a bug:
        // our own output must always be valid input.
        panic!("render output failed to re-parse:\n---\n{rendered1}\n---");
    };
    let rendered2 = lines_to_string(&lines2);

    if rendered1 != rendered2 {
        panic!(
            "render is not idempotent:\n--- first ---\n{rendered1}\n--- second ---\n{rendered2}\n---"
        );
    }
});
