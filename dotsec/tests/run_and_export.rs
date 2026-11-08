//! Integration tests for `dotsec run` and `dotsec export`, driving the real
//! binary. Stdin is /dev/null so an unexpected prompt fails fast.

use std::path::Path;
use std::process::{Command, Stdio};

fn dotsec(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> (String, String, i32) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dotsec"));
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .env_remove("DOTSEC_PRIVATE_KEY");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("failed to spawn dotsec");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code().unwrap_or(-1),
    )
}

fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(".gitignore"), "").unwrap();
    dir
}

#[test]
#[cfg(unix)]
fn run_does_not_pass_the_private_key_to_the_child() {
    let dir = fixture();
    let (_, err, code) = dotsec(dir.path(), &["set", "API_KEY", "s3cret", "--encrypt"], &[]);
    assert_eq!(code, 0, "{err}");
    let key = std::fs::read_to_string(dir.path().join(".sec.key")).unwrap();
    std::fs::remove_file(dir.path().join(".sec.key")).unwrap();

    // The key is only available through the env var; the child must see the
    // decrypted value but not the key itself.
    let (out, err, code) = dotsec(
        dir.path(),
        &[
            "run",
            "--",
            "sh",
            "-c",
            "echo \"key=${DOTSEC_PRIVATE_KEY:-unset} api=${#API_KEY}\"",
        ],
        &[("DOTSEC_PRIVATE_KEY", key.trim())],
    );
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("key=unset"),
        "child saw the private key: {out}"
    );
    assert!(out.contains("api=6"), "child should get API_KEY: {out}");
}

#[test]
#[cfg(unix)]
fn run_refuses_to_start_when_validation_fails() {
    let dir = fixture();
    // A plaintext value that violates its own @type: the file MAC deliberately
    // doesn't cover plaintext values, so validation is what must catch this.
    std::fs::write(
        dir.path().join(".env"),
        "# @provider=local\n# @default-plaintext\n\n# @type=number\nPORT=3000\n",
    )
    .unwrap();
    let (_, err, code) = dotsec(dir.path(), &["import", "-y"], &[]);
    assert_eq!(code, 0, "{err}");
    let sec = std::fs::read_to_string(dir.path().join(".sec")).unwrap();
    std::fs::write(
        dir.path().join(".sec"),
        sec.replace("PORT=3000", "PORT=not-a-number"),
    )
    .unwrap();

    let marker = dir.path().join("ran");
    let (_, err, code) = dotsec(
        dir.path(),
        &["run", "--", "touch", marker.to_str().unwrap()],
        &[],
    );
    assert_ne!(code, 0, "run must fail on invalid values");
    assert!(err.contains("Validation failed"), "{err}");
    assert!(!marker.exists(), "the child must not have been started");
}

#[test]
fn export_keeps_entries_around_a_push_only_one() {
    let dir = fixture();
    std::fs::write(
        dir.path().join(".env"),
        "# @provider=local\n# @default-plaintext\n\n# @type=number\nPORT=3000\n# @push=aws-ssm(path=\"/app/token\")\nTOKEN=abc\n# @type=number\nPORT2=4000\n",
    )
    .unwrap();
    let (_, err, code) = dotsec(dir.path(), &["import", "-y"], &[]);
    assert_eq!(code, 0, "{err}");

    let (out, err, code) = dotsec(dir.path(), &["export"], &[]);
    assert_eq!(code, 0, "{err}");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines.iter().any(|l| l.starts_with("PORT=")), "{out}");
    assert!(lines.iter().any(|l| l.starts_with("PORT2=")), "{out}");
    assert!(
        !out.contains("TOKEN"),
        "push-only entry must be excluded: {out}"
    );
    assert!(
        !out.contains("numberPORT"),
        "directive glued onto key: {out}"
    );
}
