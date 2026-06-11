//! Integration tests for `dotsec set --description` + the surrounding
//! schema-routing logic + the `extract-schema` MAC-regression fix that
//! shipped in the same commit.
//!
//! These drive the actual `dotsec` binary via `std::process::Command` so the
//! tests exercise the full pipeline (parse_args → schema discovery →
//! encrypt → write → re-read → verify). The binary path comes from Cargo's
//! `CARGO_BIN_EXE_dotsec` env var, which is set when integration tests in a
//! binary crate run — no `assert_cmd` dep needed.

use std::path::Path;
use std::process::Command;

fn dotsec_bin() -> &'static str {
    env!("CARGO_BIN_EXE_dotsec")
}

/// Run `dotsec <args>` in `cwd`. Returns (stdout, stderr, exit-code).
fn run(cwd: &Path, args: &[&str]) -> (String, String, i32) {
    let output = Command::new(dotsec_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("failed to spawn dotsec");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

/// Set up a tempdir with an empty `.gitignore` so `dotsec set` doesn't try
/// to walk up and find one in `$PROJECT/...`.
fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(".gitignore"), "").unwrap();
    dir
}

fn read(path: impl AsRef<Path>) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

// --- description routing ---

#[test]
fn description_lands_inline_when_no_schema_exists() {
    let dir = fixture();
    let (_, _, code) = run(
        dir.path(),
        &[
            "set",
            "PORT",
            "3000",
            "--description",
            "HTTP port the API listens on",
            "-y",
        ],
    );
    assert_eq!(code, 0, "set should succeed");

    let sec = read(dir.path().join(".sec"));
    assert!(
        sec.contains("@description=HTTP port the API listens on"),
        "description must be inline in .sec when no schema:\n{sec}"
    );
    assert!(sec.contains("PORT=\"3000\""), "Kv must be present: {sec}");
    // No dotsec.schema was created.
    assert!(
        !dir.path().join("dotsec.schema").exists(),
        "no schema should be created implicitly"
    );
}

#[test]
fn description_lands_in_schema_when_schema_exists_for_new_key() {
    let dir = fixture();
    // Pre-seed an empty-ish schema declaring DB_URL.
    std::fs::write(dir.path().join("dotsec.schema"), "# @encrypt\nDB_URL\n").unwrap();
    let (_, _, code) = run(
        dir.path(),
        &[
            "set",
            "DB_URL",
            "postgres://localhost/x",
            "--description",
            "Primary DB connection",
            "-y",
        ],
    );
    assert_eq!(code, 0, "set should succeed");

    let schema = read(dir.path().join("dotsec.schema"));
    assert!(
        schema.contains("@description=Primary DB connection"),
        "description must be in schema, not inline: schema=\n{schema}"
    );
    let sec = read(dir.path().join(".sec"));
    assert!(
        !sec.contains("@description"),
        "description must NOT appear in .sec when a schema took it: {sec}"
    );
}

#[test]
fn description_replaces_existing_one_on_existing_schema_key() {
    let dir = fixture();
    std::fs::write(
        dir.path().join("dotsec.schema"),
        "# @encrypt @description=old description\nDB_URL\n",
    )
    .unwrap();

    let (_, _, code) = run(
        dir.path(),
        &[
            "set",
            "DB_URL",
            "postgres://localhost/x",
            "--description",
            "new description",
            "-y",
        ],
    );
    assert_eq!(code, 0, "set should succeed");

    let schema = read(dir.path().join("dotsec.schema"));
    assert!(
        schema.contains("@description=new description"),
        "new description must be present: {schema}"
    );
    assert!(
        !schema.contains("old description"),
        "old description must be replaced, not duplicated: {schema}"
    );
    // Sanity: only one @description on this entry.
    let count = schema.matches("@description=").count();
    assert_eq!(count, 1, "exactly one @description: {schema}");
}

// --- regression: extract-schema → run round-trip ---
//
// Before the fix that ships alongside `--description`, `extract-schema`
// produced a `.sec` whose MAC verification failed on the very next read
// when `@default-encrypt` was a file-level directive (the common case
// for files created by `dotsec set` defaults).

#[test]
fn extract_schema_then_run_round_trips_cleanly() {
    let dir = fixture();
    let (_, _, code) = run(dir.path(), &["set", "PORT", "3000", "-y"]);
    assert_eq!(code, 0);

    let (_, _, code) = run(dir.path(), &["extract-schema"]);
    assert_eq!(code, 0, "extract-schema must succeed");

    // The whole point of the fix: this next call must not trip the MAC.
    let (stdout, stderr, code) = run(dir.path(), &["run", "--", "printenv", "PORT"]);
    assert_eq!(
        code, 0,
        "run after extract-schema must succeed (no MAC trip).\nstdout: {stdout}\nstderr: {stderr}"
    );
}

// --- regression: file-level directives survive an in-place update ---
//
// Before the fix, `set` updating an existing Kv would `drain` backwards
// over file-level directives (`@provider`, `@default-encrypt`, etc.)
// treating them as that Kv's per-entry directive block. Result: the file
// silently lost its file-level config and the next `run` errored with
// "Encryption engine is required."

#[test]
fn update_existing_kv_preserves_file_level_directives() {
    let dir = fixture();

    // Create the file and pull directives into a schema (so the schema-aware
    // path runs).
    let (_, _, code) = run(dir.path(), &["set", "PORT", "3000", "-y"]);
    assert_eq!(code, 0);
    let (_, _, code) = run(dir.path(), &["extract-schema"]);
    assert_eq!(code, 0);

    let before = read(dir.path().join(".sec"));
    assert!(
        before.contains("@provider=local"),
        "fixture should have @provider=local file-level: {before}"
    );

    // Update the existing key — under the previous bug this would drop the
    // @provider line.
    let (_, _, code) = run(
        dir.path(),
        &["set", "PORT", "4000", "--description", "new", "-y"],
    );
    assert_eq!(code, 0);

    let after = read(dir.path().join(".sec"));
    assert!(
        after.contains("@provider=local"),
        "@provider=local must survive in-place update: {after}"
    );
    // The Kv may be plain (PORT=4000) or encrypted (PORT=ENC[…]) depending
    // on the schema's @encrypt-vs-@plaintext resolution — the point of
    // this test is the file-level directives don't get drained, not the
    // encryption decision. So we check via `dotsec show` instead.
    let (stdout, stderr, code) = run(dir.path(), &["show", "--reveal"]);
    assert_eq!(
        code, 0,
        "show after update must succeed.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("PORT=4000"),
        "show must return the new value:\nstdout: {stdout}"
    );
}
