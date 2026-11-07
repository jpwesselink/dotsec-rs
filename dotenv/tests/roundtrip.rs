//! Stable-toolchain twin of the `roundtrip` fuzz target (fuzz/fuzz_targets/
//! roundtrip.rs), so every PR checks the invariant instead of only the
//! nightly fuzz run:
//!
//!   if `parse(x)` succeeds, `render(parse(x))` must re-parse, and rendering
//!   that again must give the same text (render/parse reach a fixed point).
//!
//! A violation means a value or key can mutate or vanish across an
//! encrypt → decrypt → write cycle.

use dotenv::{lines_to_string, parse_dotenv, Line};
use proptest::prelude::*;
use std::path::Path;

fn check_roundtrip(src: &str) -> Result<(), String> {
    let Ok(lines1) = parse_dotenv(src) else {
        return Ok(()); // rejecting input is fine; panicking or drifting is not
    };
    let r1 = lines_to_string(&lines1);
    let lines2 =
        parse_dotenv(&r1).map_err(|e| format!("render output failed to re-parse:\n{r1:?}\n{e}"))?;
    let r2 = lines_to_string(&lines2);
    if r1 != r2 {
        return Err(format!("render not idempotent:\n{r1:?}\n{r2:?}"));
    }
    Ok(())
}

/// Every fuzz seed — including minimized reproducers of past findings —
/// must satisfy the invariant. Add new crash reproducers to
/// `fuzz/seeds/roundtrip/` and they're covered here automatically.
#[test]
fn fuzz_seeds_round_trip() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuzz/seeds/roundtrip");
    let mut n = 0;
    for entry in std::fs::read_dir(&dir).expect("fuzz/seeds/roundtrip exists") {
        let path = entry.unwrap().path();
        let bytes = std::fs::read(&path).unwrap();
        let Ok(src) = std::str::from_utf8(&bytes) else {
            continue;
        };
        if let Err(e) = check_roundtrip(src) {
            panic!("{}: {e}", path.display());
        }
        n += 1;
    }
    assert!(n > 0, "no seeds found in {}", dir.display());
}

/// Building blocks that have historically mattered: line endings incl. lone
/// `\r`, blanks, quotes, comment/directive starters, `export`, escapes, and
/// some non-ASCII / Unicode whitespace.
fn fragment() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => prop::sample::select(vec![
            "\n", "\r\n", "\r", " ", "\t", "\u{b}", "\u{a0}",
            "=", "\"", "'", "`", "\\", "#", "//", "@", "# @", "#@",
            "export", "export ", "FOO", "A", "_b.c-d", "${", "}",
            "@encrypt", "@region=", "@type=", "string", "@push=", "@min=",
            "@deprecated", "@dotsec(", ")", "\\n", "\\u00e9", "é", "\0",
        ])
        .prop_map(str::to_string),
        1 => any::<char>().prop_map(|c| c.to_string()),
    ]
}

fn source() -> impl Strategy<Value = String> {
    prop::collection::vec(fragment(), 0..48).prop_map(|v| v.concat())
}

/// One well-formed unquoted kv line plus the (key, value) it must parse to.
/// Values deliberately include `#`, `//`, `@`, blanks and `=` — the shapes
/// that used to be swallowed as comments or dropped with their key.
fn kv_line() -> impl Strategy<Value = (String, String, String)> {
    let key = "[A-Za-z_][A-Za-z0-9_.-]{0,8}"
        .prop_filter("`export` is the prefix keyword", |k| k != "export");
    let value = prop::collection::vec(
        prop::sample::select(vec![
            "a", "Z", "0", "#", "//", "/", "@", "=", ":", ".", "-", "_", " ", "\t", "é", "${X}",
        ]),
        0..10,
    )
    .prop_map(|v| v.concat())
    // Leading blanks belong to the separator, not the value.
    .prop_filter("no leading blank", |v| !v.starts_with([' ', '\t']));
    let export = prop::sample::select(vec!["", "export ", "export\t", "export  "]);
    let blank = prop::sample::select(vec!["", " ", "\t", "  "]);
    (export, key, blank.clone(), blank, value)
        .prop_map(|(e, k, b1, b2, v)| (format!("{e}{k}{b1}={b2}{v}"), k, v))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, ..ProptestConfig::default() })]

    #[test]
    fn render_parse_is_a_fixed_point(src in source()) {
        if let Err(e) = check_roundtrip(&src) {
            prop_assert!(false, "{e}\ninput: {src:?}");
        }
    }

    #[test]
    fn schema_parse_never_panics(src in source()) {
        let _ = dotenv::parse_schema(&src);
    }

    /// No silent data loss: every generated kv comes out with its exact key
    /// and value, in order. (The fixed-point property alone can't see a kv
    /// that is dropped *consistently*.)
    #[test]
    fn kv_lines_are_preserved(
        lines in prop::collection::vec(kv_line(), 1..8),
        eol in prop::sample::select(vec!["\n", "\r\n"]),
    ) {
        let src: String = lines.iter().map(|(l, _, _)| format!("{l}{eol}")).collect();
        let parsed = parse_dotenv(&src).map_err(|e| TestCaseError::fail(format!("{e}\ninput: {src:?}")))?;
        let got: Vec<(String, String)> = parsed
            .into_iter()
            .filter_map(|l| match l {
                Line::Kv { key, value, .. } => Some((key, value)),
                _ => None,
            })
            .collect();
        let want: Vec<(String, String)> = lines.into_iter().map(|(_, k, v)| (k, v)).collect();
        prop_assert_eq!(got, want, "input: {:?}", src);
    }
}
