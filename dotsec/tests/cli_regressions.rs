//! Regression tests for non-interactive CLI flows:
//!
//! - `dotsec import -y` in a fresh directory must not prompt.
//! - `dotsec set ... --push <target> -y` must keep the `@push` directive.
//! - `dotsec extract-schema` must not change which entries are encrypted, and
//!   must render file-level directives as file-level in the schema.
//!
//! Like `set_description.rs`, these drive the real binary with stdin wired to
//! `/dev/null` so any unexpected prompt fails fast instead of hanging.

use std::path::Path;
use std::process::{Command, Stdio};

fn run(cwd: &Path, args: &[&str]) -> (String, String, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_dotsec"))
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .expect("failed to spawn dotsec");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(".gitignore"), "").unwrap();
    dir
}

fn read(path: impl AsRef<Path>) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Return the raw on-disk value line for `key` in a `.sec` file.
fn kv_line<'a>(sec: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key}=");
    sec.lines()
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no {key}= line in:\n{sec}"))
}

// --- import -y ---

#[test]
fn import_yes_in_fresh_dir_uses_local_encrypt_defaults_without_prompting() {
    let dir = fixture();
    std::fs::write(dir.path().join(".env"), "API_KEY=sk-123\nPORT=3000\n").unwrap();

    let (stdout, stderr, code) = run(dir.path(), &["import", "-y"]);
    assert_eq!(
        code, 0,
        "import -y must not prompt.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let sec = read(dir.path().join(".sec"));
    assert!(sec.contains("@provider=local"), "local provider: {sec}");
    assert!(sec.contains("@default-encrypt"), "default-encrypt: {sec}");
    assert!(dir.path().join(".sec.key").exists(), "keypair generated");
    assert!(
        kv_line(&sec, "API_KEY").contains("ENC["),
        "secret must be encrypted: {sec}"
    );

    let (stdout, stderr, code) = run(dir.path(), &["show", "--reveal"]);
    assert_eq!(code, 0, "show must succeed: {stderr}");
    assert!(stdout.contains("sk-123"), "decrypted value: {stdout}");
}

// --- set --push -y ---

#[test]
fn set_push_with_yes_keeps_push_directive() {
    let dir = fixture();
    let (_, stderr, code) = run(
        dir.path(),
        &["set", "API_KEY", "v", "--push", "aws-ssm", "-y"],
    );
    assert_eq!(code, 0, "set should succeed: {stderr}");

    let sec = read(dir.path().join(".sec"));
    assert!(
        sec.contains("@push=aws-ssm"),
        "@push must be written with -y:\n{sec}"
    );
}

#[test]
fn set_push_with_yes_keeps_push_directive_in_schema() {
    let dir = fixture();
    // Bootstrap a .sec, then a schema, then add a new key with --push -y.
    let (_, stderr, code) = run(dir.path(), &["set", "FIRST", "1", "--type", "number", "-y"]);
    assert_eq!(code, 0, "{stderr}");
    let (_, stderr, code) = run(dir.path(), &["extract-schema"]);
    assert_eq!(code, 0, "{stderr}");

    let (_, stderr, code) = run(
        dir.path(),
        &[
            "set",
            "API_KEY",
            "v",
            "--push",
            "aws-secrets-manager",
            "--also-env",
            "-y",
        ],
    );
    assert_eq!(code, 0, "set should succeed: {stderr}");

    let schema = read(dir.path().join("dotsec.schema"));
    assert!(
        schema.contains("@push=aws-secrets-manager") && schema.contains("@also-env"),
        "@push/@also-env must land in the schema with -y:\n{schema}"
    );
    let (_, stderr, code) = run(dir.path(), &["show", "--reveal"]);
    assert_eq!(code, 0, "show must succeed: {stderr}");
}

// --- extract-schema ---

const SEC_WITH_PLAINTEXT: &str = "\
# @provider=local @default-encrypt

# @plaintext @type=number
PORT=\"3000\"

# @type=string
SECRET=\"hunter2\"
";

#[test]
fn extract_schema_preserves_encryption_state_and_file_level_directives() {
    let dir = fixture();
    // Create the keypair + an encrypted .sec via the CLI, then overwrite the
    // body with our fixture and re-encrypt it.
    let (_, stderr, code) = run(dir.path(), &["set", "BOOT", "x", "-y"]);
    assert_eq!(code, 0, "{stderr}");
    std::fs::remove_file(dir.path().join(".sec")).unwrap();
    std::fs::write(dir.path().join(".sec"), SEC_WITH_PLAINTEXT).unwrap();
    let (_, stderr, code) = run(dir.path(), &["encrypt"]);
    assert_eq!(code, 0, "encrypt failed: {stderr}");

    let before = read(dir.path().join(".sec"));
    assert_eq!(kv_line(&before, "PORT"), "PORT=\"3000\"", "{before}");
    assert!(kv_line(&before, "SECRET").contains("ENC["), "{before}");

    let (stdout, stderr, code) = run(dir.path(), &["extract-schema"]);
    assert_eq!(code, 0, "extract-schema failed:\n{stdout}\n{stderr}");

    let after = read(dir.path().join(".sec"));
    assert_eq!(
        kv_line(&after, "PORT"),
        "PORT=\"3000\"",
        "@plaintext entry must stay plaintext after extract-schema:\n{after}"
    );
    assert!(
        kv_line(&after, "SECRET").contains("ENC["),
        "encrypted entry must stay encrypted:\n{after}"
    );

    // File-level directive is its own block in the schema, not glued onto
    // the first key's directive line.
    let schema = read(dir.path().join("dotsec.schema"));
    let first_line = schema.lines().next().unwrap_or_default();
    assert_eq!(first_line, "# @default-encrypt", "schema:\n{schema}");
    assert!(
        schema.contains("\n\n# @plaintext @type=number\nPORT\n"),
        "PORT's directives must not include the file-level one:\n{schema}"
    );

    // MAC (which covers the schema hash) still verifies.
    let (stdout, stderr, code) = run(dir.path(), &["show", "--reveal"]);
    assert_eq!(code, 0, "show must succeed after extract-schema: {stderr}");
    assert!(stdout.contains("hunter2"), "{stdout}");
    assert!(stdout.contains("3000"), "{stdout}");

    // A later re-encrypt (via set) must also keep PORT plaintext.
    let (_, stderr, code) = run(dir.path(), &["set", "SECRET", "rotated", "-y"]);
    assert_eq!(code, 0, "{stderr}");
    let after_set = read(dir.path().join(".sec"));
    assert_eq!(kv_line(&after_set, "PORT"), "PORT=\"3000\"", "{after_set}");
    assert!(
        kv_line(&after_set, "SECRET").contains("ENC["),
        "{after_set}"
    );
    let (_, stderr, code) = run(dir.path(), &["show", "--reveal"]);
    assert_eq!(code, 0, "show must succeed after set: {stderr}");
}
