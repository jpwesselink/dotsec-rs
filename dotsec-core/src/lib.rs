pub use dotenv;
use dotenv::{lines_to_entries, Line, Schema};
use std::path::Path;

mod configuration;
pub use configuration::*;

// --- File helpers ---

pub fn load_file(file: &str) -> Result<String, std::io::Error> {
    std::fs::read_to_string(file)
}

/// Write content to a .sec or schema file with restricted permissions (0600 on Unix).
///
/// Writes via a sibling temp file + atomic rename so a malicious symlink at `path`
/// cannot be used to overwrite the symlink's target. Refuses outright if `path` is
/// already a symlink (preserves user intent — we won't silently replace one).
pub fn write_sec_file(path: &str, content: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::path::{Path, PathBuf};

    let path = Path::new(path);

    // Refuse to write through a symlink. The rename below replaces the symlink itself
    // (not its target) so this check isn't strictly required for safety, but it
    // prevents silently breaking any legitimate symlink the user may have placed.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(format!("refusing to write through symlink: {}", path.display()).into());
        }
    }

    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or("invalid output path: missing file name")?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(
        ".{}.tmp.{}.{}",
        name.to_string_lossy(),
        std::process::id(),
        nanos,
    ));

    // Drop guard: if we error out before the successful rename, remove the temp file
    // so a crashed write doesn't leak partial plaintext or stale temp files.
    struct TempCleanup(Option<PathBuf>);
    impl Drop for TempCleanup {
        fn drop(&mut self) {
            if let Some(p) = self.0.take() {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    let mut cleanup = TempCleanup(Some(tmp.clone()));

    let mut file = open_temp_write(&tmp)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    drop(file);

    std::fs::rename(&tmp, path)?;
    cleanup.0 = None; // success — keep the renamed file
    Ok(())
}

#[cfg(unix)]
fn open_temp_write(tmp: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp)
}

#[cfg(not(unix))]
fn open_temp_write(tmp: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)
}

// --- Header ---

pub mod header_v3;

/// Version stamped into new `.sec` file headers — major.minor.patch derived from the
/// crate's compile-time `CARGO_PKG_VERSION`. Prerelease and build-metadata suffixes
/// are intentionally stripped so prereleases of the same line (eg
/// `6.0.1-fix-foo.SHA`) stamp the same `6.0.1` and headers don't churn in git on
/// every PR install. (`has_header` matches the bare `# dotsec v` prefix so headers
/// stamped by older majors continue to be recognized.)
pub fn header_version() -> &'static str {
    let v = env!("CARGO_PKG_VERSION");
    // Split on '-' or '+' (semver prerelease / build separators) and take the head.
    match v.find(['-', '+']) {
        Some(idx) => &v[..idx],
        None => v,
    }
}

/// Generate the standard dotsec file header (two comment lines + newlines).
pub fn generate_header() -> Vec<Line> {
    vec![
        Line::Comment {
            text: format!(
                "# dotsec v{} — encrypted environment file",
                header_version()
            ),
        },
        Line::Newline,
        Line::Comment {
            text: "# https://github.com/jpwesselink/dotsec-rs".into(),
        },
        Line::Newline,
    ]
}

/// Check whether parsed lines contain the dotsec header.
pub fn has_header(lines: &[Line]) -> bool {
    lines
        .iter()
        .any(|line| matches!(line, Line::Comment { text } if text.starts_with("# dotsec v")))
}

pub fn parse_content(content: &str) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    Ok(dotenv::parse_dotenv(content)?)
}

// --- Constants ---

/// Build the standard KMS `EncryptionContext` that dotsec passes to every
/// `GenerateDataKey` / `Decrypt` call. Today this is just `dotsec:format=v3`:
/// a format-confusion guard plus a stable IAM-policy hook (security teams
/// can pin `dotsec:format=v3` to specific roles).
///
/// Symmetric: same context on encrypt and decrypt. If the keys/values ever
/// diverge between code paths, KMS will refuse to unwrap with `InvalidCiphertext`.
pub fn kms_encryption_context() -> aws::EncryptionContext {
    vec![("dotsec:format".to_string(), "v3".to_string())]
}

/// User-facing copy for integrity verification failure. Plain English, no
/// jargon. Phrased so running `dotsec encrypt` only sounds like the right
/// call when the user actually changed something themselves.
pub const MAC_FAILURE_MESSAGE: &str = "The .sec file has changed in a way \
dotsec can't verify.\n\
\n\
Something an attacker could weaponize \u{2014} a directive, an ENC[\u{2026}] \
value, the schema, or the set of entries in the file \u{2014} doesn't match \
the integrity tag stored when the file was last written by dotsec.\n\
\n\
Two ways this happens:\n\
\n\
  1. You (or a teammate) hand-edited the file. Common cases that trip this:\n\
       \u{2022} adding or removing a variable (encrypted or plaintext);\n\
       \u{2022} renaming or reordering a variable;\n\
       \u{2022} editing a directive on an *encrypted* entry (e.g. `@encrypt`,\n\
         `@push`, `@key-id`, `@type`);\n\
       \u{2022} editing an ENC[\u{2026}] payload or the schema file.\n\
     To accept the new state, run:\n\
\n\
       dotsec encrypt\n\
\n\
     This refreshes the integrity tag against what's currently on disk. (Tip:\n\
     prefer `dotsec set` for routine edits \u{2014} it re-MACs automatically.)\n\
\n\
  2. Someone tampered with the file. Running `dotsec encrypt` now would \
silently bless the tamper. Restore from git or your last known good backup \
and investigate before doing anything else.\n\
\n\
What DOESN'T trip this error:\n\
  \u{2022} editing a plaintext value in place (e.g. `PORT=3000` \u{2192} `PORT=4000`);\n\
  \u{2022} editing an inline directive on a *plaintext* entry (move the\n\
    directive into `dotsec.schema` if you need integrity for it);\n\
  \u{2022} reformatting whitespace or editing comments.\n\
\n\
If your edit was strictly one of those and you still see this message, \
please report it as a bug.";

/// On MAC failure, try to localize the drift by diffing the current file's
/// MAC inputs against the version at `git show HEAD:<sec_file>`. Returns
/// `Some(report)` when a meaningful diff was produced, `None` when the file
/// isn't in git, git isn't available, the HEAD copy doesn't parse, or there
/// is no detectable difference (which is itself a real signal — the file
/// matches HEAD bit-for-bit but the MAC still fails, meaning the *schema*
/// drifted; we surface that too).
///
/// All git invocations are read-only. Any error or non-zero exit is treated
/// as "no comparison available" and yields `None`, so the diagnostic stays
/// an additive enhancement: callers append its output to `MAC_FAILURE_MESSAGE`
/// when present, fall back to today's message otherwise.
pub fn diagnose_mac_drift_against_git_head(sec_file: &str) -> Option<String> {
    use std::process::Command;
    use std::process::Stdio;

    fn run(args: &[&str], cwd: Option<&Path>) -> Option<Vec<u8>> {
        let mut cmd = Command::new("git");
        cmd.args(args).stdin(Stdio::null()).stderr(Stdio::null());
        if let Some(d) = cwd {
            cmd.current_dir(d);
        }
        let out = cmd.output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(out.stdout)
    }

    let abs = std::fs::canonicalize(sec_file).ok()?;
    let cwd = abs.parent()?;
    // Repo root, so we can compute the path git knows.
    let toplevel_bytes = run(&["rev-parse", "--show-toplevel"], Some(cwd))?;
    let toplevel = std::str::from_utf8(&toplevel_bytes).ok()?.trim();
    let toplevel = Path::new(toplevel);
    let rel = abs.strip_prefix(toplevel).ok()?;
    let rel_str = rel.to_str()?;

    // Confirm the file is actually tracked at HEAD before pulling content.
    run(
        &["ls-tree", "--name-only", "HEAD", "--", rel_str],
        Some(toplevel),
    )?;
    let head_bytes = run(&["show", &format!("HEAD:{rel_str}")], Some(toplevel))?;
    let head_str = std::str::from_utf8(&head_bytes).ok()?;
    let head_lines = dotenv::parse_dotenv(head_str).ok()?;

    let current_str = std::fs::read_to_string(sec_file).ok()?;
    let current_lines = dotenv::parse_dotenv(&current_str).ok()?;

    let mut bullets: Vec<String> = Vec::new();
    diff_file_level_directives(&head_lines, &current_lines, &mut bullets);
    diff_entries(&head_lines, &current_lines, &mut bullets);

    if bullets.is_empty() {
        // No detectable diff in MAC inputs means the schema (or schema_hash arg)
        // is the offender. Tell the user where to look without pretending we
        // know which schema file changed.
        return Some(
            "\n\nSpecific drift vs git HEAD: no per-entry changes detected. \
            The schema referenced when encrypting has changed (or a different \
            schema is being used now). Compare your current `dotsec.schema` \
            against HEAD with `git diff HEAD -- dotsec.schema` (or whatever \
            path your `DOTSEC_SCHEMA` points at)."
                .to_string(),
        );
    }

    let mut out = String::from("\n\nSpecific drift vs git HEAD:\n");
    for b in bullets {
        out.push_str(&format!("  \u{2022} {b}\n"));
    }
    Some(out)
}

fn diff_file_level_directives(head: &[Line], current: &[Line], bullets: &mut Vec<String>) {
    fn first_kv_directives(lines: &[Line]) -> Vec<(String, Option<String>)> {
        let mut out = Vec::new();
        for line in lines {
            match line {
                Line::Kv { .. } => break,
                Line::Directive { name, value } if name != header_v3::HEADER_DIRECTIVE_NAME => {
                    out.push((name.clone(), value.clone()));
                }
                _ => {}
            }
        }
        out
    }
    let head_dirs = first_kv_directives(head);
    let cur_dirs = first_kv_directives(current);
    if head_dirs == cur_dirs {
        return;
    }
    let render = |d: &(String, Option<String>)| match &d.1 {
        Some(v) => format!("@{}={}", d.0, v),
        None => format!("@{}", d.0),
    };
    // Simple per-name diff — gives readable output even when both sides reorder.
    use std::collections::BTreeSet;
    let head_names: BTreeSet<&String> = head_dirs.iter().map(|(n, _)| n).collect();
    let cur_names: BTreeSet<&String> = cur_dirs.iter().map(|(n, _)| n).collect();
    for added in cur_names.difference(&head_names) {
        if let Some(d) = cur_dirs.iter().find(|(n, _)| &n == added) {
            bullets.push(format!("file-level directive added: {}", render(d)));
        }
    }
    for removed in head_names.difference(&cur_names) {
        if let Some(d) = head_dirs.iter().find(|(n, _)| &n == removed) {
            bullets.push(format!("file-level directive removed: {}", render(d)));
        }
    }
    for shared in head_names.intersection(&cur_names) {
        let h = head_dirs.iter().find(|(n, _)| &n == shared);
        let c = cur_dirs.iter().find(|(n, _)| &n == shared);
        if let (Some(h), Some(c)) = (h, c) {
            if h.1 != c.1 {
                bullets.push(format!(
                    "file-level directive changed: {} → {}",
                    render(h),
                    render(c)
                ));
            }
        }
    }
}

fn diff_entries(head: &[Line], current: &[Line], bullets: &mut Vec<String>) {
    use std::collections::BTreeMap;
    let head_entries = dotenv::lines_to_entries(head);
    let cur_entries = dotenv::lines_to_entries(current);
    let head_map: BTreeMap<&str, &dotenv::Entry> =
        head_entries.iter().map(|e| (e.key.as_str(), e)).collect();
    let cur_map: BTreeMap<&str, &dotenv::Entry> =
        cur_entries.iter().map(|e| (e.key.as_str(), e)).collect();

    for key in cur_map.keys() {
        if !head_map.contains_key(key) {
            bullets.push(format!("entry added: {key}"));
        }
    }
    for key in head_map.keys() {
        if !cur_map.contains_key(key) {
            bullets.push(format!("entry removed: {key}"));
        }
    }
    for (key, head_e) in &head_map {
        let cur_e = match cur_map.get(key) {
            Some(e) => e,
            None => continue,
        };
        // Per-entry directive diff (name set + per-name value).
        let head_dir_set: BTreeMap<&str, Option<&str>> = head_e
            .directives
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_deref()))
            .collect();
        let cur_dir_set: BTreeMap<&str, Option<&str>> = cur_e
            .directives
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_deref()))
            .collect();
        if head_dir_set != cur_dir_set {
            bullets.push(format!(
                "directives on {key} changed: was {} → now {}",
                fmt_dir_set(&head_dir_set),
                fmt_dir_set(&cur_dir_set)
            ));
        }
        // Value diff — only meaningful for entries whose on-disk value is part
        // of the MAC, which is the encrypted ones (ENC[…]). Plaintext value
        // edits don't trip MAC, so don't report them as drift.
        let head_enc = head_e.value.starts_with("ENC[");
        let cur_enc = cur_e.value.starts_with("ENC[");
        if (head_enc || cur_enc) && head_e.value != cur_e.value {
            bullets.push(format!(
                "ENC[\u{2026}] value of {key} changed (ciphertext differs from HEAD)"
            ));
        }
    }
}

fn fmt_dir_set(dirs: &std::collections::BTreeMap<&str, Option<&str>>) -> String {
    if dirs.is_empty() {
        return "(none)".to_string();
    }
    let parts: Vec<String> = dirs
        .iter()
        .map(|(n, v)| match v {
            Some(v) => format!("@{n}={v}"),
            None => format!("@{n}"),
        })
        .collect();
    parts.join(" ")
}

/// Wrap a per-value `CryptoError` with the key name + a concrete recovery
/// hint. Without this, a malformed `ENC[abc]c]`-style envelope bubbles up
/// the raw `base64 decoding failed: Invalid byte 0x5d, offset 2` from the
/// base64 crate, which is unactionable. The wrapped form names the key and
/// points the user at the same recovery commands the MAC-failure message
/// uses, since the user's likely next move is the same.
fn wrap_decrypt_error(key: &str, err: crypto::CryptoError) -> Box<dyn std::error::Error> {
    use crypto::CryptoError;
    match &err {
        CryptoError::DecodeError(_) | CryptoError::InvalidFormat => format!(
            "Couldn't decrypt {key}: its ENC[\u{2026}] envelope is malformed ({err}).\n\
\n\
This usually means the file was hand-edited inside the ENC[\u{2026}] payload \
or partially corrupted. Either restore the file from git (preferred — the \
on-disk ciphertext is unrecoverable as-is) or, if you intentionally cleared \
the value, run `dotsec set {key} <new-value>` to write a fresh ciphertext."
        )
        .into(),
        _ => format!("Couldn't decrypt {key}: {err}").into(),
    }
}

// --- Format detection ---

/// Classify a .sec file by its envelope. Used to decide whether to write a
/// fresh file (None), refuse to overwrite (Unparseable), or preserve the
/// existing `@dotsec(...)` directive on re-encrypt.
fn detect_format(lines: &[Line]) -> SecFormat {
    if header_v3::HeaderV3::is_present(lines) {
        SecFormat::Recognized
    } else {
        SecFormat::None
    }
}

#[derive(Debug, PartialEq)]
enum SecFormat {
    Recognized,  // Has an `@dotsec(...)` directive — proper dotsec file
    None,        // No encryption markers (new file)
    Unparseable, // File exists but couldn't be parsed — refuse to write rather than silently bump
}

// --- Encrypt ---

/// Merge schema-owned directives into a list of entries so the caller sees
/// `@encrypt`/`@plaintext` (and `@type`, `@push`, …) even when they live in
/// `dotsec.schema` rather than inline on the entry.
///
/// Conflict resolution:
/// - Inline `@encrypt`/`@plaintext` on an entry win as a pair: if either is
///   set, both are skipped from the schema so the user's local override sticks.
/// - Other directives: only added when the entry doesn't already have them.
/// - Schema-level `@default-encrypt` applies when the entry has no
///   inline-or-schema `@encrypt`/`@plaintext` decision yet.
///
/// **Use this in any command that re-encrypts** — `rotate-key`, `dotsec
/// encrypt`, etc. Skipping the merge causes a plaintext leak: a value that's
/// encrypted via schema-only `@encrypt` would otherwise be treated as
/// plaintext and re-written without encryption.
pub fn merge_schema_directives_into_entries(
    entries: &mut [dotenv::Entry],
    schema: Option<&Schema>,
) {
    let Some(schema) = schema else {
        return;
    };
    let schema_default_encrypt: Option<bool> = schema
        .iter()
        .flat_map(|(_, e)| e.directives.iter())
        .find_map(|(name, _)| match name.as_str() {
            "default-encrypt" => Some(true),
            "default-plaintext" => Some(false),
            _ => None,
        });

    for entry in entries.iter_mut() {
        let inline_encryption_override = entry
            .directives
            .iter()
            .any(|(n, _)| n == "encrypt" || n == "plaintext");

        if let Some(schema_entry) = schema.get(&entry.key) {
            for (name, value) in &schema_entry.directives {
                if name == "default-encrypt" || name == "default-plaintext" {
                    continue;
                }
                if (name == "encrypt" || name == "plaintext") && inline_encryption_override {
                    continue;
                }
                if !entry.directives.iter().any(|(n, _)| n == name) {
                    entry.directives.push((name.clone(), value.clone()));
                }
            }
        }
        if !inline_encryption_override
            && !entry
                .directives
                .iter()
                .any(|(n, _)| n == "encrypt" || n == "plaintext")
        {
            if let Some(true) = schema_default_encrypt {
                entry.directives.push(("encrypt".to_string(), None));
            }
        }
    }
}

/// Encrypt in-memory lines and write the result to a .sec file.
///
/// For each entry with `@encrypt`:
///   - Encrypt the value with the DEK → `ENC[base64(commitment||nonce||ciphertext||tag)]`
///
/// The DEK is wrapped by KMS and stored as `__DOTSEC_KEY__="base64(wrapped_dek)"`.
pub async fn encrypt_lines_to_sec(
    lines: &[Line],
    sec_file: &str,
    encryption_engine: &EncryptionEngine,
    schema: Option<&Schema>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut entries = lines_to_entries(lines);
    merge_schema_directives_into_entries(&mut entries, schema);

    let (dek, wrapped_dek) = match encryption_engine {
        EncryptionEngine::Aws(opts) => {
            let key_id = opts.key_id.as_deref().ok_or("AWS key_id is required")?;
            let region = opts.region.as_deref();
            match load_existing_dek_aws(sec_file, region).await {
                Ok(pair) => pair,
                Err(e) => {
                    let is_new = is_new_or_no_key(&e);
                    if is_new {
                        aws::generate_data_key(key_id, region, &kms_encryption_context()).await?
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        EncryptionEngine::Local(opts) => {
            let private_key = crypto::local::load_private_key(sec_file, opts.key_file.as_deref())?;
            let recipient = crypto::local::recipient_from_identity(&private_key)?;
            match load_existing_dek_local(sec_file, &private_key) {
                Ok(pair) => pair,
                Err(e) => {
                    let is_new = is_new_or_no_key(&e);
                    if is_new {
                        let dek = crypto::generate_dek();
                        let wrapped = crypto::local::wrap_dek(&dek, &recipient)?;
                        (dek, wrapped)
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        EncryptionEngine::None => return Err("Encryption engine is required".into()),
    };

    // Derive the schema hash inside the encrypt path from the schema we just
    // merged. Doing this here (vs. as a separate caller-supplied parameter)
    // prevents the class of bugs where the caller passes a startup-computed
    // hash that's now stale because the same caller just modified the schema
    // mid-flight (extract-schema, migrate). One source of truth.
    let schema_hash = match schema {
        Some(s) => crypto::mac::schema_hash(Some(&dotenv::schema_to_canonical_bytes(s))),
        None => crypto::mac::schema_hash(None),
    };

    encrypt_with_dek(lines, &entries, &dek, &wrapped_dek, sec_file, &schema_hash)
}

#[allow(clippy::borrowed_box)]
fn is_new_or_no_key(e: &Box<dyn std::error::Error>) -> bool {
    let is_new_file = e
        .downcast_ref::<std::io::Error>()
        .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::NotFound);
    let is_no_key = e.to_string().contains("No @dotsec(...) directive found");
    is_new_file || is_no_key
}

/// Inner encryption logic, separated so the caller can zeroize the DEK.
///
/// Refuses to overwrite a file that exists but doesn't parse — we'd lose the
/// user's in-progress bytes. Reads the on-disk file (not the caller's
/// in-memory `lines`) to make that determination, since callers pass
/// post-decryption lines that have had the header stripped.
fn encrypt_with_dek(
    lines: &[Line],
    entries: &[dotenv::Entry],
    dek: &[u8],
    wrapped_dek: &[u8],
    sec_file: &str,
    schema_hash: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    if select_target_format(sec_file) == SecFormat::Unparseable {
        return Err(format!(
            "Cannot write {sec_file}: the existing file exists but doesn't parse as a \
             dotenv-style file. Fix the syntax (or remove the file if you intended to \
             start fresh) before re-running."
        )
        .into());
    }

    let mut sec_lines: Vec<Line> = Vec::new();

    for line in lines {
        match line {
            Line::Kv {
                key,
                value,
                quote_type,
            } => {
                let entry = entries.iter().find(|e| e.key == *key);
                let should_encrypt = entry.is_some_and(|e| e.has_directive("encrypt"));

                if should_encrypt {
                    if crypto::is_encrypted_value(value) {
                        sec_lines.push(line.clone());
                    } else {
                        let encrypted = crypto::encrypt_value(value, dek, key)?;
                        sec_lines.push(Line::Kv {
                            key: key.clone(),
                            value: encrypted,
                            quote_type: quote_type.clone(),
                        });
                    }
                } else {
                    sec_lines.push(line.clone());
                }
            }
            // Drop any pre-existing @dotsec(...) directive — we'll recompute
            // and re-insert below. Other directives flow through unchanged.
            Line::Directive { name, .. } if name == header_v3::HEADER_DIRECTIVE_NAME => continue,
            other => sec_lines.push(other.clone()),
        }
    }

    let mac = compute_v3_mac(&sec_lines, dek, schema_hash);
    let header = header_v3::HeaderV3 {
        mac,
        wrapped_dek: wrapped_dek.to_vec(),
    };
    insert_v3_header(&mut sec_lines, header);

    let output = dotenv::lines_to_string(&sec_lines);
    write_sec_file(sec_file, &output)?;

    Ok(())
}

/// Pick the wire format for `encrypt_with_dek`'s output by reading the
/// on-disk file directly. Reading the on-disk bytes — not the caller's
/// in-memory `lines` — is what enforces the no-silent-bump invariant:
/// post-decryption lines have already had their v2/v3 envelope stripped, so
/// they can't distinguish the original format.
///
/// Mapping:
/// - File on disk has `@dotsec(...)` directive → `Recognized`
/// - File on disk has `__DOTSEC_KEY__` Kv line → `V2` (stays V2; user opts
///   into v3 via `dotsec upgrade-format`)
/// - File on disk has `__DOTSEC__` Kv line → `V1` (legacy; encrypt path
///   refuses, user must `dotsec migrate`)
/// - File missing → `None` (new file, caller writes v3 by default)
/// - File exists but doesn't parse → `Unparseable`. The caller MUST refuse to
///   write rather than treat it as a new file — silently writing v3 over an
///   unparseable v2 file would be an irreversible format bump that loses the
///   user's original bytes.
fn select_target_format(sec_file: &str) -> SecFormat {
    let Ok(content) = std::fs::read_to_string(sec_file) else {
        return SecFormat::None;
    };
    let Ok(lines) = dotenv::parse_dotenv(&content) else {
        return SecFormat::Unparseable;
    };
    detect_format(&lines)
}

/// Compute the v3 file MAC from on-disk `sec_lines` + `schema_hash`.
///
/// The canonical input is a pure function of what's *on disk* — no merged-schema
/// view is folded in. The schema's contribution to integrity comes solely from
/// `schema_hash` (which `canonical_serialize` embeds). This keeps encrypt and
/// decrypt symmetric: both sides reconstruct the canonical from the same
/// source (`lines_to_entries` over the file's lines + `schema_hash`).
///
/// Public because `rotate-key` legitimately needs to mint a v3 file under a
/// fresh DEK (the encrypt path reads the existing DEK from disk and can't be
/// asked to use a new one). Other callers should go through
/// [`encrypt_lines_to_sec`].
pub fn compute_v3_mac(sec_lines: &[Line], dek: &[u8], schema_hash: &[u8; 32]) -> [u8; 32] {
    let canonical = build_canonical_bytes(sec_lines, schema_hash);
    crypto::compute_file_mac(dek, &canonical)
}

/// Canonical-input builder shared by encrypt and decrypt. Pure function of
/// `(sec_lines, schema_hash)` — both sides derive the same bytes from the same
/// on-disk state, which is what makes MAC verification work.
fn build_canonical_bytes(sec_lines: &[Line], schema_hash: &[u8; 32]) -> Vec<u8> {
    use crypto::mac::{canonical_serialize, CanonicalEntry};

    // File-level directives stop at the first Kv (matches extract_file_config's contract).
    // The `@dotsec(...)` directive carries the integrity tag itself — it must
    // be excluded from the canonical input, otherwise the MAC would have to
    // include itself.
    let mut file_directives: Vec<(String, Option<String>)> = Vec::new();
    for line in sec_lines {
        match line {
            Line::Kv { .. } => break,
            Line::Directive { name, value } if name != header_v3::HEADER_DIRECTIVE_NAME => {
                file_directives.push((name.clone(), value.clone()));
            }
            _ => {}
        }
    }

    // Per-entry view: inline directives + on-disk value. lines_to_entries
    // also applies file-level @default-encrypt / @default-plaintext, which is
    // part of the file's authoritative semantics — keep it in the canonical.
    let entries = dotenv::lines_to_entries(sec_lines);
    let canonical_entries: Vec<CanonicalEntry> = entries
        .iter()
        .map(|e| CanonicalEntry {
            key: e.key.clone(),
            directives: e.directives.clone(),
            value: e.value.clone(),
        })
        .collect();

    canonical_serialize(&file_directives, &canonical_entries, schema_hash)
}

/// Insert the `@dotsec(...)` directive into `sec_lines`. **Does not replace**
/// an existing directive — callers must strip any pre-existing one before
/// calling. The encrypt path does this via the `Line::Directive { name: "dotsec", .. }`
/// filter.
///
/// Placement: after the banner comment block (the two-line `# dotsec v…` +
/// `# https://github.com/jpwesselink/dotsec-rs` pair). If the banner has a
/// user-edited comment interleaved between its two lines, the header lands
/// between the first banner line and the user's comment — still valid, but
/// cosmetically odd. Files written by dotsec never produce that shape.
///
/// Public for the same reason as [`compute_v3_mac`] — `rotate-key` needs it.
pub fn insert_v3_header(sec_lines: &mut Vec<Line>, header: header_v3::HeaderV3) {
    let header_line = header.to_directive_line();

    // Find insertion point: after the entire banner block (banner Comments +
    // their interleaved Newlines), before the first Directive/Kv/non-banner
    // Comment. For a file with no banner, falls through to insert_at=0.
    let mut insert_at = 0usize;
    for (i, line) in sec_lines.iter().enumerate() {
        match line {
            Line::Comment { text }
                if text.starts_with("# dotsec v")
                    || text.starts_with("# https://github.com/jpwesselink") =>
            {
                insert_at = i + 1;
            }
            Line::Newline if insert_at > 0 => {
                // Banner-internal newline — keep extending past it.
                insert_at = i + 1;
            }
            _ => break,
        }
    }

    sec_lines.insert(insert_at, header_line);
    sec_lines.insert(insert_at + 1, Line::Newline);
}

// --- Decrypt ---

/// Decrypt a .sec file and return resolved lines with plaintext values.
pub async fn decrypt_sec_to_lines(
    sec_file: &str,
    encryption_engine: &EncryptionEngine,
    schema_hash: &[u8; 32],
) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    decrypt_sec_to_lines_inner(sec_file, encryption_engine, Some(schema_hash)).await
}

/// **Privileged**: decrypt without verifying the v3 file-level MAC. This
/// is the chicken-and-egg path for `dotsec encrypt` — that command is what
/// *produces* a fresh MAC, so it can't verify one first. Per-value AEAD still
/// authenticates each `ENC[…]` payload, so this is NOT a blanket bypass of
/// cryptographic integrity; it's only the file-level MAC that's skipped.
///
/// The name spells out the contract because there is no other legitimate use:
/// every other caller MUST go through [`decrypt_sec_to_lines`]. If your new
/// code reaches for this function, you are almost certainly building the
/// wrong abstraction — talk to the maintainers first.
///
/// Visibility: `pub(crate)` *inside* this crate; re-exported as
/// `pub` only via a re-export in `dotsec` so the single CLI command can
/// call it. Don't widen the visibility further.
pub async fn decrypt_sec_to_lines_for_remac_only(
    sec_file: &str,
    encryption_engine: &EncryptionEngine,
) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    decrypt_sec_to_lines_inner(sec_file, encryption_engine, None).await
}

/// Inner decrypt. `schema_hash` semantics:
/// - `Some(h)` → verify the v3 MAC against this schema hash.
/// - `None`    → skip v3 MAC verification entirely (the re-MAC path).
///
/// Using `Option` instead of a `bool` + sentinel makes "no MAC verify" a
/// type-level decision, not a value-level one. A future contributor who adds
/// a third schema-related check can't silently inherit the wrong behavior.
async fn decrypt_sec_to_lines_inner(
    sec_file: &str,
    encryption_engine: &EncryptionEngine,
    schema_hash: Option<&[u8; 32]>,
) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    let content = load_file(sec_file)?;
    let lines = dotenv::parse_dotenv(&content)?;

    match detect_format(&lines) {
        SecFormat::Recognized => decrypt_v3(sec_file, &lines, encryption_engine, schema_hash).await,
        // detect_format() runs on already-parsed lines, so Unparseable
        // can't reach here — parse failure already returned via the `?` above.
        SecFormat::Unparseable => unreachable!("detect_format never returns Unparseable"),
        SecFormat::None => {
            let has_enc_values = lines.iter().any(|l| {
                if let Line::Kv { value: v, .. } = l {
                    crypto::is_encrypted_value(v)
                } else {
                    false
                }
            });
            if has_enc_values {
                return Err(
                    "File contains ENC[...] values but no @dotsec(...) directive. File may be corrupted."
                        .into(),
                );
            }
            Ok(lines)
        }
    }
}

/// Read a `.sec` file: parse the `@dotsec(...)` directive, verify the file-level
/// integrity tag (when `schema_hash` is `Some`), unwrap the DEK, decrypt
/// every `ENC[…]` value, and return the result as plaintext lines.
///
/// `schema_hash = None` is the privileged re-MAC path used by `dotsec encrypt`
/// — it skips file-level integrity verification but still authenticates each
/// ciphertext via per-value AEAD.
async fn decrypt_v3(
    sec_file: &str,
    lines: &[Line],
    encryption_engine: &EncryptionEngine,
    schema_hash: Option<&[u8; 32]>,
) -> Result<Vec<Line>, Box<dyn std::error::Error>> {
    let parsed = header_v3::HeaderV3::extract_from_lines(lines)
        .map_err(|e| format!("file is missing its @dotsec(...) header directive: {e}"))?;

    let dek = match encryption_engine {
        EncryptionEngine::Aws(opts) => {
            aws::unwrap_data_key(
                &parsed.wrapped_dek,
                opts.region.as_deref(),
                &kms_encryption_context(),
            )
            .await?
        }
        EncryptionEngine::Local(opts) => {
            let private_key = crypto::local::load_private_key(sec_file, opts.key_file.as_deref())?;
            crypto::local::unwrap_dek(&parsed.wrapped_dek, &private_key)?
        }
        EncryptionEngine::None => return Err("Encryption engine is required".into()),
    };

    if let Some(schema_hash) = schema_hash {
        // The header directive is filtered out of the canonical bytes inside
        // `build_canonical_bytes` (it would otherwise be self-referencing —
        // the MAC can't include itself).
        let canonical = build_canonical_bytes(lines, schema_hash);
        crypto::verify_file_mac(&dek, &canonical, &parsed.mac).map_err(|_| {
            let mut msg = MAC_FAILURE_MESSAGE.to_string();
            if let Some(diag) = diagnose_mac_drift_against_git_head(sec_file) {
                msg.push_str(&diag);
            }
            Box::<dyn std::error::Error>::from(msg)
        })?;
    }

    let mut resolved: Vec<Line> = Vec::new();
    for line in lines {
        match line {
            Line::Directive { name, .. } if name == header_v3::HEADER_DIRECTIVE_NAME => continue,
            Line::Kv {
                key,
                value,
                quote_type,
            } => {
                if crypto::is_encrypted_value(value) {
                    let plaintext = crypto::decrypt_value(value, &dek, key)
                        .map_err(|e| wrap_decrypt_error(key, e))?;
                    resolved.push(Line::Kv {
                        key: key.clone(),
                        value: plaintext,
                        quote_type: quote_type.clone(),
                    });
                } else {
                    resolved.push(line.clone());
                }
            }
            _ => resolved.push(line.clone()),
        }
    }
    Ok(resolved)
}

// --- DEK helpers ---

type DekPair = (zeroize::Zeroizing<Vec<u8>>, Vec<u8>);

/// Read the wrapped DEK from an existing .sec file's `@dotsec(...)` directive.
/// Returns a clean "no header" error when the file exists but has no
/// recognized envelope (the encrypt path treats this as "new file →
/// generate fresh DEK").
fn load_existing_wrapped_dek(sec_file: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let content = load_file(sec_file)?;
    let lines = dotenv::parse_dotenv(&content)?;
    let parsed = header_v3::HeaderV3::extract_from_lines(&lines)
        .map_err(|_| "No @dotsec(...) directive found")?;
    Ok(parsed.wrapped_dek)
}

async fn load_existing_dek_aws(
    sec_file: &str,
    region: Option<&str>,
) -> Result<DekPair, Box<dyn std::error::Error>> {
    let wrapped_dek = load_existing_wrapped_dek(sec_file)?;
    let dek = aws::unwrap_data_key(&wrapped_dek, region, &kms_encryption_context()).await?;
    Ok((dek, wrapped_dek))
}

fn load_existing_dek_local(
    sec_file: &str,
    identity: &str,
) -> Result<DekPair, Box<dyn std::error::Error>> {
    let wrapped_dek = load_existing_wrapped_dek(sec_file)?;
    let dek = crypto::local::unwrap_dek(&wrapped_dek, identity)?;
    Ok((dek, wrapped_dek))
}

// --- Run helpers ---

/// Extract key-value pairs from lines and resolve `${VAR}` interpolation.
///
/// Only double-quoted and unquoted values are interpolated; single-quoted values stay literal.
///
/// Entries marked `@push=…` are excluded by default (they're owned by the push target),
/// unless they also carry `@also-env`. This rule was introduced in v6.0.0. See
/// `Entry::injects_into_env`.
pub fn resolve_env_vars(lines: &[Line]) -> Vec<(String, String)> {
    let entries = lines_to_entries(lines);
    let mut resolved: Vec<(String, String)> = Vec::new();

    for line in lines {
        if let Line::Kv {
            key,
            value,
            quote_type,
        } = line
        {
            // Push-only entries (no `@also-env`) are owned by the push target, not the env.
            // `lines_to_entries` already merges file-level @default-* defaults.
            let entry = entries.iter().find(|e| e.key == *key);
            if entry.is_some_and(|e| !e.injects_into_env()) {
                continue;
            }
            let final_value = match quote_type {
                dotenv::QuoteType::Single => value.clone(),
                _ => interpolate(value, &resolved),
            };
            resolved.push((key.clone(), final_value));
        }
    }

    resolved
}

/// Replace `${VAR}` and `$VAR` patterns with values from the resolved map.
fn interpolate(value: &str, resolved: &[(String, String)]) -> String {
    let mut result = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' {
            if chars.peek() == Some(&'{') {
                chars.next(); // consume '{'
                let mut var_name = String::new();
                while chars.peek().is_some_and(|c| *c != '}') {
                    var_name.push(chars.next().unwrap());
                }
                if chars.peek() == Some(&'}') {
                    chars.next(); // consume '}'
                    let val = lookup(&var_name, resolved);
                    result.push_str(&val);
                } else {
                    // Unclosed ${ — treat as literal text
                    eprintln!(
                        "warning: unclosed ${{{}}} in value, treating as literal text",
                        var_name
                    );
                    result.push_str("${");
                    result.push_str(&var_name);
                }
            } else if chars
                .peek()
                .is_some_and(|c| c.is_ascii_alphabetic() || *c == '_')
            {
                let mut var_name = String::new();
                while chars
                    .peek()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
                {
                    var_name.push(chars.next().unwrap());
                }
                let val = lookup(&var_name, resolved);
                result.push_str(&val);
            } else {
                result.push('$');
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Look up a variable from the resolved list, falling back to the process environment.
fn lookup(name: &str, resolved: &[(String, String)]) -> String {
    for (k, v) in resolved.iter().rev() {
        if k == name {
            return v.clone();
        }
    }
    std::env::var(name).unwrap_or_default()
}

/// Drop push-only entries (and their preceding directive block) from a parsed line stream.
///
/// Used by `dotsec export` so a `KEY=value` consumed downstream as a `.env` file matches
/// what `dotsec run` would inject — push-only entries stay out of both. Comments, whitespace,
/// and non-push entries are preserved verbatim. See `Entry::injects_into_env`.
pub fn filter_env_injectable_lines(lines: &[Line]) -> Vec<Line> {
    use std::collections::HashSet;

    let entries = lines_to_entries(lines);
    let excluded_keys: HashSet<&str> = entries
        .iter()
        .filter(|e| !e.injects_into_env())
        .map(|e| e.key.as_str())
        .collect();

    if excluded_keys.is_empty() {
        return lines.to_vec();
    }

    let mut out: Vec<Line> = Vec::with_capacity(lines.len());
    let mut pending_directives: Vec<Line> = Vec::new();

    for line in lines {
        match line {
            Line::Directive { .. } => {
                pending_directives.push(line.clone());
            }
            Line::Kv { key, .. } => {
                if excluded_keys.contains(key.as_str()) {
                    // Drop both the kv and its preceding directive block (and trailing newline).
                    pending_directives.clear();
                    if matches!(out.last(), Some(Line::Newline)) {
                        out.pop();
                    }
                } else {
                    out.append(&mut pending_directives);
                    out.push(line.clone());
                }
            }
            Line::Comment { .. } => {
                // Comments terminate directive chains; flush pending.
                out.append(&mut pending_directives);
                out.push(line.clone());
            }
            _ => out.push(line.clone()),
        }
    }

    // Any trailing pending directives without a kv (shouldn't happen in well-formed input,
    // but preserve them rather than silently drop).
    out.append(&mut pending_directives);
    out
}

/// Collect the values of entries marked `@encrypt` from the resolved env vars.
pub fn collect_secret_values(lines: &[Line], env_vars: &[(String, String)]) -> Vec<String> {
    let entries = lines_to_entries(lines);
    let mut secrets = Vec::new();
    for entry in &entries {
        if entry.has_directive("encrypt") {
            if let Some((_, val)) = env_vars.iter().find(|(k, _)| k == &entry.key) {
                if !val.is_empty() {
                    secrets.push(val.clone());
                }
            }
        }
    }
    // Sort longest first so we replace longer matches before shorter substrings
    secrets.sort_by_key(|b| std::cmp::Reverse(b.len()));
    secrets
}

/// Replace all occurrences of secret values in a string with asterisks.
pub fn redact(line: &str, secrets: &[String]) -> String {
    let mut result = line.to_string();
    for secret in secrets {
        result = result.replace(secret, &"*".repeat(secret.len()));
    }
    result
}

#[cfg(test)]
mod kms_context_tests {
    use super::*;

    #[test]
    fn kms_encryption_context_pins_format_v3() {
        // This contract is load-bearing for KMS: changing it silently means
        // every existing wrapped DEK becomes un-decryptable. If a future
        // change adds a field, do it as an additive migration with a
        // documented re-wrap path — never by editing this constant in place.
        let ctx = kms_encryption_context();
        assert_eq!(ctx, vec![("dotsec:format".to_string(), "v3".to_string())]);
    }

    #[test]
    fn kms_encryption_context_is_deterministic() {
        // Order matters to KMS — same key/value pairs in a different order
        // are treated as identical, but our code path appends in a fixed
        // sequence and we want to keep it that way for diffability of
        // any future audit log dumps.
        let a = kms_encryption_context();
        let b = kms_encryption_context();
        assert_eq!(a, b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dotenv::{Line, QuoteType};

    // --- write_sec_file ---

    #[test]
    #[cfg(unix)]
    fn write_sec_file_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join("dotsec-test-write-sec");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.sec");

        write_sec_file(path.to_str().unwrap(), "SECRET=hunter2\n").unwrap();

        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- header ---

    #[test]
    fn generate_header_has_two_comment_lines() {
        let header = generate_header();
        let comments: Vec<_> = header
            .iter()
            .filter(|l| matches!(l, Line::Comment { .. }))
            .collect();
        assert_eq!(comments.len(), 2);
    }

    #[test]
    fn generate_header_first_line_contains_current_version() {
        let header = generate_header();
        // Same stripping rule as the impl: drop anything after '-' or '+'.
        let raw = env!("CARGO_PKG_VERSION");
        let expected_version = match raw.find(['-', '+']) {
            Some(i) => &raw[..i],
            None => raw,
        };
        let expected = format!("dotsec v{}", expected_version);
        assert!(matches!(&header[0], Line::Comment { text } if text.contains(&expected)));
    }

    #[test]
    fn generate_header_second_line_contains_url() {
        let header = generate_header();
        assert!(
            matches!(&header[2], Line::Comment { text } if text.contains("https://github.com/jpwesselink/dotsec-rs"))
        );
    }

    #[test]
    fn has_header_true_when_present() {
        let lines = generate_header();
        assert!(has_header(&lines));
    }

    #[test]
    fn has_header_recognizes_older_majors() {
        // The `# dotsec v` prefix is intentionally version-agnostic so files
        // stamped by older majors (v5, etc.) keep being recognized after we ship a
        // newer major.
        let v5_header = vec![
            Line::Comment {
                text: "# dotsec v5 — encrypted environment file".into(),
            },
            Line::Newline,
        ];
        assert!(has_header(&v5_header));
    }

    #[test]
    fn has_header_false_when_absent() {
        let lines = vec![
            Line::Comment {
                text: "# just a comment".into(),
            },
            Line::Newline,
            Line::Kv {
                key: "FOO".into(),
                value: "bar".into(),
                quote_type: QuoteType::None,
            },
        ];
        assert!(!has_header(&lines));
    }

    #[test]
    fn has_header_matches_any_version() {
        let lines = vec![Line::Comment {
            text: "# dotsec v99 — encrypted environment file".into(),
        }];
        assert!(has_header(&lines));
    }

    // --- interpolate ---

    #[test]
    fn interpolate_braced_var() {
        let resolved = vec![("FOO".into(), "100".into())];
        assert_eq!(interpolate("val is ${FOO}", &resolved), "val is 100");
    }

    #[test]
    fn interpolate_unbraced_var() {
        let resolved = vec![("FOO".into(), "100".into())];
        assert_eq!(interpolate("val is $FOO!", &resolved), "val is 100!");
    }

    #[test]
    fn interpolate_missing_var_yields_empty() {
        let resolved: Vec<(String, String)> = vec![];
        assert_eq!(interpolate("${NOPE}", &resolved), "");
    }

    #[test]
    fn interpolate_multiple_vars() {
        let resolved = vec![("A".into(), "hello".into()), ("B".into(), "world".into())];
        assert_eq!(interpolate("${A} ${B}", &resolved), "hello world");
    }

    #[test]
    fn interpolate_bare_dollar_preserved() {
        let resolved: Vec<(String, String)> = vec![];
        assert_eq!(interpolate("price is $5", &resolved), "price is $5");
    }

    #[test]
    fn interpolate_no_vars() {
        let resolved: Vec<(String, String)> = vec![];
        assert_eq!(interpolate("plain text", &resolved), "plain text");
    }

    #[test]
    fn interpolate_unclosed_brace_is_literal() {
        let resolved = vec![("A".into(), "val".into())];
        assert_eq!(
            interpolate("path is ${UNCLOSED", &resolved),
            "path is ${UNCLOSED"
        );
    }

    #[test]
    fn interpolate_unclosed_brace_mixed() {
        let resolved = vec![("A".into(), "val".into())];
        assert_eq!(
            interpolate("${A} then ${UNCLOSED", &resolved),
            "val then ${UNCLOSED"
        );
    }

    // --- push-only env exclusion (v6 breaking change) ---

    #[test]
    fn resolve_env_vars_excludes_push_only_entries() {
        // @push without @also-env: belongs to the push target, not the env.
        let lines =
            parse_content("# @push=aws-ssm\nDB_PASSWORD=\"secret\"\n\nFOO=\"bar\"\n").unwrap();
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved, vec![("FOO".into(), "bar".into())]);
        assert!(!resolved.iter().any(|(k, _)| k == "DB_PASSWORD"));
    }

    #[test]
    fn resolve_env_vars_includes_push_when_also_env() {
        // @push + @also-env: opt back in to env injection.
        let lines = parse_content("# @push=aws-ssm @also-env\nDB_PASSWORD=\"secret\"\n").unwrap();
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved, vec![("DB_PASSWORD".into(), "secret".into())]);
    }

    #[test]
    fn filter_env_injectable_lines_drops_push_only_block() {
        let lines = parse_content(
            "# @encrypt\n# @push=aws-ssm\nDB_PASSWORD=\"secret\"\n\n# @encrypt\nAPI_KEY=\"k\"\n",
        )
        .unwrap();
        let filtered = filter_env_injectable_lines(&lines);
        let rendered = dotenv::lines_to_string(&filtered);
        assert!(!rendered.contains("DB_PASSWORD"));
        assert!(!rendered.contains("aws-ssm"));
        assert!(rendered.contains("API_KEY=\"k\""));
    }

    #[test]
    fn filter_env_injectable_lines_keeps_push_with_also_env() {
        let lines = parse_content("# @push=aws-ssm @also-env\nDB_PASSWORD=\"secret\"\n").unwrap();
        let filtered = filter_env_injectable_lines(&lines);
        let rendered = dotenv::lines_to_string(&filtered);
        assert!(rendered.contains("DB_PASSWORD=\"secret\""));
    }

    // --- resolve_env_vars ---

    #[test]
    fn resolve_env_vars_basic() {
        let lines = vec![
            Line::Kv {
                key: "FOO".into(),
                value: "bar".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "BAZ".into(),
                value: "qux".into(),
                quote_type: QuoteType::None,
            },
        ];
        let resolved = resolve_env_vars(&lines);
        assert_eq!(
            resolved,
            vec![("FOO".into(), "bar".into()), ("BAZ".into(), "qux".into()),]
        );
    }

    #[test]
    fn resolve_env_vars_interpolation() {
        let lines = vec![
            Line::Kv {
                key: "HOST".into(),
                value: "localhost".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "URL".into(),
                value: "http://${HOST}:3000".into(),
                quote_type: QuoteType::Double,
            },
        ];
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved[1].1, "http://localhost:3000");
    }

    #[test]
    fn resolve_env_vars_single_quote_no_interpolation() {
        let lines = vec![
            Line::Kv {
                key: "HOST".into(),
                value: "localhost".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "LITERAL".into(),
                value: "${HOST}".into(),
                quote_type: QuoteType::Single,
            },
        ];
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved[1].1, "${HOST}");
    }

    // --- format detection ---

    #[test]
    fn detect_no_format() {
        let lines = vec![Line::Kv {
            key: "FOO".into(),
            value: "bar".into(),
            quote_type: QuoteType::Double,
        }];
        assert_eq!(detect_format(&lines), SecFormat::None);
    }

    #[test]
    fn detect_none_with_enc_values_but_no_dotsec_key() {
        // ENC[...] values present but no __DOTSEC_KEY__ or __DOTSEC__ marker
        let lines = vec![
            Line::Kv {
                key: "SECRET".into(),
                value: "ENC[base64data]".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "OTHER".into(),
                value: "ENC[moredata]".into(),
                quote_type: QuoteType::Double,
            },
        ];
        assert_eq!(detect_format(&lines), SecFormat::None);
    }

    #[test]
    fn detect_none_for_empty_lines() {
        let lines: Vec<Line> = vec![];
        assert_eq!(detect_format(&lines), SecFormat::None);
    }

    #[test]
    fn detect_none_for_only_comments_and_newlines() {
        let lines = vec![
            Line::Comment {
                text: "# just a comment".into(),
            },
            Line::Newline,
            Line::Newline,
        ];
        assert_eq!(detect_format(&lines), SecFormat::None);
    }

    // --- redact ---

    #[test]
    fn redact_replaces_secrets() {
        let secrets = vec!["s3cret".to_string()];
        assert_eq!(
            redact("my password is s3cret", &secrets),
            "my password is ******"
        );
    }

    #[test]
    fn redact_multiple_secrets() {
        let secrets = vec!["longersecret".to_string(), "short".to_string()];
        assert_eq!(
            redact("short and longersecret here", &secrets),
            "***** and ************ here"
        );
    }

    #[test]
    fn redact_no_secrets() {
        let secrets: Vec<String> = vec![];
        assert_eq!(redact("nothing to hide", &secrets), "nothing to hide");
    }

    #[test]
    fn redact_secret_appearing_multiple_times() {
        let secrets = vec!["tok".to_string()];
        assert_eq!(redact("tok and tok again", &secrets), "*** and *** again");
    }

    // --- collect_secret_values ---

    #[test]
    fn collect_secrets_only_encrypted_entries() {
        let lines = vec![
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "SECRET".into(),
                value: "shhh".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "PUBLIC".into(),
                value: "visible".into(),
                quote_type: QuoteType::None,
            },
        ];
        let env_vars = vec![
            ("SECRET".into(), "shhh".into()),
            ("PUBLIC".into(), "visible".into()),
        ];
        let secrets = collect_secret_values(&lines, &env_vars);
        assert_eq!(secrets, vec!["shhh"]);
    }

    #[test]
    fn collect_secrets_sorted_longest_first() {
        let lines = vec![
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "A".into(),
                value: "ab".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "B".into(),
                value: "abcdef".into(),
                quote_type: QuoteType::Double,
            },
        ];
        let env_vars = vec![("A".into(), "ab".into()), ("B".into(), "abcdef".into())];
        let secrets = collect_secret_values(&lines, &env_vars);
        assert_eq!(secrets, vec!["abcdef", "ab"]);
    }

    #[test]
    fn collect_secrets_skips_empty_values() {
        let lines = vec![
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "EMPTY".into(),
                value: "".into(),
                quote_type: QuoteType::Double,
            },
        ];
        let env_vars = vec![("EMPTY".into(), "".into())];
        let secrets = collect_secret_values(&lines, &env_vars);
        assert!(secrets.is_empty());
    }

    // --- detect_format tests ---

    #[test]
    fn detect_enc_values_without_key_is_none() {
        let lines = vec![Line::Kv {
            key: "SECRET".into(),
            value: "ENC[base64data]".into(),
            quote_type: QuoteType::Double,
        }];
        assert!(matches!(detect_format(&lines), SecFormat::None));
    }

    #[test]
    fn detect_empty_lines_is_none() {
        let lines: Vec<Line> = vec![];
        assert!(matches!(detect_format(&lines), SecFormat::None));
    }

    // --- Plaintext .sec roundtrip tests ---

    #[test]
    fn plaintext_sec_roundtrip() {
        // Create lines with @default-plaintext + some Kv entries
        let lines = vec![
            Line::Directive {
                name: "default-plaintext".into(),
                value: None,
            },
            Line::Newline,
            Line::Newline,
            Line::Kv {
                key: "FOO".into(),
                value: "bar".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "PORT".into(),
                value: "3000".into(),
                quote_type: QuoteType::None,
            },
            Line::Newline,
        ];

        // Serialize to string
        let content = dotenv::lines_to_string(&lines);

        // Parse back and verify values match
        let reparsed = dotenv::parse_dotenv(&content).unwrap();
        let entries = dotenv::lines_to_entries(&reparsed);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "FOO");
        assert_eq!(entries[0].value, "bar");
        assert_eq!(entries[1].key, "PORT");
        assert_eq!(entries[1].value, "3000");
    }

    #[test]
    fn detect_format_none_for_plaintext_file() {
        // A file with no ENC[...] values and no __DOTSEC_KEY__
        let lines = vec![
            Line::Directive {
                name: "default-plaintext".into(),
                value: None,
            },
            Line::Newline,
            Line::Newline,
            Line::Kv {
                key: "FOO".into(),
                value: "bar".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "PORT".into(),
                value: "3000".into(),
                quote_type: QuoteType::None,
            },
            Line::Newline,
        ];
        assert_eq!(detect_format(&lines), SecFormat::None);
    }

    #[test]
    fn sec_format_none_with_enc_values_detected() {
        // A file with ENC[...] values but NO __DOTSEC_KEY__
        let lines = vec![
            Line::Kv {
                key: "SECRET".into(),
                value: "ENC[base64data]".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "OTHER".into(),
                value: "ENC[moredata]".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];

        // detect_format returns None (no __DOTSEC_KEY__)
        assert_eq!(detect_format(&lines), SecFormat::None);

        // But we can detect the ENC values are present, which should be an error condition
        let has_enc_values = lines.iter().any(|l| {
            if let Line::Kv { value: v, .. } = l {
                crypto::is_encrypted_value(v)
            } else {
                false
            }
        });
        assert!(has_enc_values, "ENC values should be detected");

        // This combination (ENC values without __DOTSEC_KEY__) indicates a corrupted file
    }

    // --- redact (extended) ---

    #[test]
    fn redact_across_full_line() {
        let secrets = vec!["entire-line-is-secret".to_string()];
        let redacted = redact("entire-line-is-secret", &secrets);
        assert_eq!(
            redacted,
            "*".repeat("entire-line-is-secret".len()),
            "a secret that spans the full line should be fully masked"
        );
    }

    #[test]
    fn redact_preserves_non_secret_content() {
        let secrets = vec!["hidden".to_string()];
        let result = redact("prefix hidden suffix", &secrets);
        assert_eq!(result, "prefix ****** suffix");
        assert!(result.contains("prefix"));
        assert!(result.contains("suffix"));
        assert!(!result.contains("hidden"));
    }

    #[test]
    fn redact_empty_secrets_list() {
        let secrets: Vec<String> = vec![];
        let line = "nothing changes here";
        assert_eq!(redact(line, &secrets), line);
    }

    #[test]
    fn collect_and_redact_integration() {
        // Parse a .sec-style string with @encrypt directive
        let sec_content =
            "# @encrypt\nDB_PASSWORD=\"super-secret-pw\"\nPUBLIC_URL=http://example.com\n";
        let lines = dotenv::parse_dotenv(sec_content).unwrap();

        // Resolve env vars
        let env_vars = resolve_env_vars(&lines);
        assert_eq!(env_vars.len(), 2);

        // Collect secret values (only @encrypt entries)
        let secrets = collect_secret_values(&lines, &env_vars);
        assert_eq!(secrets, vec!["super-secret-pw"]);

        // Redact a line containing one of the secret values
        let output_line = "connecting to DB with password super-secret-pw ...";
        let redacted = redact(output_line, &secrets);
        assert!(
            !redacted.contains("super-secret-pw"),
            "secret value should be masked"
        );
        assert!(
            redacted.contains("***************"),
            "masked value should be asterisks of same length"
        );
        assert!(
            redacted.contains("connecting to DB with password"),
            "non-secret text should be preserved"
        );
    }

    // --- resolve_env_vars (extended for run --using env) ---

    #[test]
    fn resolve_env_vars_from_plain_env() {
        let env_content = "APP_NAME=myapp\nPORT=8080\nDEBUG=true\n";
        let lines = dotenv::parse_dotenv(env_content).unwrap();
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved.len(), 3);
        assert_eq!(resolved[0], ("APP_NAME".into(), "myapp".into()));
        assert_eq!(resolved[1], ("PORT".into(), "8080".into()));
        assert_eq!(resolved[2], ("DEBUG".into(), "true".into()));
    }

    #[test]
    fn resolve_env_vars_with_interpolation() {
        let env_content = "BASE=\"http://localhost\"\nURL=\"${BASE}/api\"\n";
        let lines = dotenv::parse_dotenv(env_content).unwrap();
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0], ("BASE".into(), "http://localhost".into()));
        assert_eq!(resolved[1], ("URL".into(), "http://localhost/api".into()));
    }

    #[test]
    fn resolve_env_vars_single_quotes_no_interpolation() {
        let env_content = "HOST=\"localhost\"\nLITERAL='${HOST}/path'\n";
        let lines = dotenv::parse_dotenv(env_content).unwrap();
        let resolved = resolve_env_vars(&lines);
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0], ("HOST".into(), "localhost".into()));
        assert_eq!(
            resolved[1],
            ("LITERAL".into(), "${HOST}/path".into()),
            "single-quoted values should not interpolate"
        );
    }

    #[test]
    fn plaintext_lines_to_string_roundtrip_with_directives() {
        let source =
            "# @default-plaintext\n\n# @type=string\nFOO=\"hello\"\n\n# @type=number\nPORT=3000\n";
        let lines = dotenv::parse_dotenv(source).unwrap();
        let output = dotenv::lines_to_string(&lines);
        assert_eq!(output, source);

        // Re-parse and validate entries
        let reparsed = dotenv::parse_dotenv(&output).unwrap();
        let entries = dotenv::lines_to_entries(&reparsed);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "FOO");
        assert_eq!(entries[0].value, "hello");
        assert!(
            !entries[0].has_directive("encrypt"),
            "plaintext default should not add encrypt"
        );
    }

    // --- local encryption integration ---

    #[tokio::test]
    async fn local_encrypt_decrypt_roundtrip() {
        let dir = std::env::temp_dir().join("dotsec-test-local-roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();

        let (identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();

        let lines = vec![
            Line::Directive {
                name: "provider".to_string(),
                value: Some("local".to_string()),
            },
            Line::Newline,
            Line::Directive {
                name: "encrypt".to_string(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "SECRET".into(),
                value: "hunter2".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Kv {
                key: "PUBLIC".into(),
                value: "hello".into(),
                quote_type: QuoteType::None,
            },
            Line::Newline,
        ];

        let engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(key_file.clone()),
        });

        encrypt_lines_to_sec(&lines, &sec_file, &engine, None)
            .await
            .unwrap();

        let content = std::fs::read_to_string(&sec_file).unwrap();
        assert!(
            content.contains("ENC["),
            "encrypted value should contain ENC[...]"
        );
        assert!(
            content.contains("@dotsec("),
            "new files should carry the @dotsec(...) directive"
        );
        assert!(
            content.contains("mac="),
            "@dotsec(...) should include the file integrity tag"
        );
        assert!(
            !content.contains("__DOTSEC_KEY__"),
            "v7 should not emit any legacy __DOTSEC_KEY__ Kv line"
        );
        assert!(!content.contains("hunter2"), "plaintext should not appear");

        let decrypted = decrypt_sec_to_lines(&sec_file, &engine, &crypto::mac::empty_schema_hash())
            .await
            .unwrap();
        let secret_val = decrypted.iter().find_map(|l| {
            if let Line::Kv { key, value, .. } = l {
                if key == "SECRET" {
                    Some(value.clone())
                } else {
                    None
                }
            } else {
                None
            }
        });
        assert_eq!(secret_val.as_deref(), Some("hunter2"));

        let public_val = decrypted.iter().find_map(|l| {
            if let Line::Kv { key, value, .. } = l {
                if key == "PUBLIC" {
                    Some(value.clone())
                } else {
                    None
                }
            } else {
                None
            }
        });
        assert_eq!(public_val.as_deref(), Some("hello"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn local_decrypt_with_wrong_key_fails() {
        let dir = std::env::temp_dir().join("dotsec-test-local-wrong-key");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();
        let wrong_key_file = dir.join("wrong.sec.key").to_string_lossy().to_string();

        let (identity, _) = crypto::local::generate_keypair();
        let (wrong_identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();
        std::fs::write(&wrong_key_file, &wrong_identity).unwrap();

        let lines = vec![
            Line::Directive {
                name: "encrypt".to_string(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "SECRET".into(),
                value: "hunter2".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];

        let engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(key_file),
        });

        encrypt_lines_to_sec(&lines, &sec_file, &engine, None)
            .await
            .unwrap();

        let wrong_engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(wrong_key_file),
        });
        let result =
            decrypt_sec_to_lines(&sec_file, &wrong_engine, &crypto::mac::empty_schema_hash()).await;
        assert!(result.is_err(), "decrypting with wrong key should fail");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn local_decrypt_discovers_sibling_key_file() {
        let dir = std::env::temp_dir().join("dotsec-test-local-discovery");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();

        let (identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();

        let lines = vec![
            Line::Directive {
                name: "encrypt".to_string(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "SECRET".into(),
                value: "hunter2".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];

        let encrypt_engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(key_file.clone()),
        });
        encrypt_lines_to_sec(&lines, &sec_file, &encrypt_engine, None)
            .await
            .unwrap();

        // Decrypt with key_file: None — must auto-discover <sec>.key.
        let decrypt_engine = EncryptionEngine::Local(LocalEncryptionOptions { key_file: None });
        let decrypted = decrypt_sec_to_lines(
            &sec_file,
            &decrypt_engine,
            &crypto::mac::empty_schema_hash(),
        )
        .await
        .unwrap();
        let secret_val = decrypted.iter().find_map(|l| {
            if let Line::Kv { key, value, .. } = l {
                if key == "SECRET" {
                    Some(value.clone())
                } else {
                    None
                }
            } else {
                None
            }
        });
        assert_eq!(secret_val.as_deref(), Some("hunter2"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn schema_owned_encrypt_directive_still_encrypts() {
        // Regression: when @encrypt lives in dotsec.schema (not inline in .sec),
        // encrypt_lines_to_sec must still encrypt the value. Pre-fix this silently wrote
        // plaintext, leaking secrets on rewrite paths (format, extract-schema, remove-directives).
        let dir = std::env::temp_dir().join("dotsec-test-schema-encrypt");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();
        let (identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();

        // Build a schema where @encrypt is schema-owned for DB_PASSWORD.
        let schema = dotenv::parse_schema("# @encrypt\nDB_PASSWORD\n").unwrap();

        // .sec lines with no inline @encrypt directive.
        let lines = vec![
            Line::Kv {
                key: "DB_PASSWORD".into(),
                value: "secret123".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];

        let engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(key_file),
        });
        encrypt_lines_to_sec(&lines, &sec_file, &engine, Some(&schema))
            .await
            .unwrap();

        let on_disk = std::fs::read_to_string(&sec_file).unwrap();
        assert!(
            on_disk.contains("ENC["),
            "schema-owned @encrypt should still encrypt: {}",
            on_disk
        );
        assert!(
            !on_disk.contains("secret123"),
            "plaintext leaked to disk: {}",
            on_disk
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn schema_default_encrypt_still_encrypts() {
        // Regression: when @default-encrypt lives in dotsec.schema (file-level), all entries
        // without explicit @plaintext should still be encrypted.
        let dir = std::env::temp_dir().join("dotsec-test-schema-default-encrypt");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();
        let (identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();

        let schema = dotenv::parse_schema("# @default-encrypt\n\nDB_PASSWORD\n").unwrap();

        let lines = vec![
            Line::Kv {
                key: "DB_PASSWORD".into(),
                value: "secret123".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];

        let engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(key_file),
        });
        encrypt_lines_to_sec(&lines, &sec_file, &engine, Some(&schema))
            .await
            .unwrap();

        let on_disk = std::fs::read_to_string(&sec_file).unwrap();
        assert!(
            on_disk.contains("ENC["),
            "schema @default-encrypt should encrypt: {}",
            on_disk
        );
        assert!(
            !on_disk.contains("secret123"),
            "plaintext leaked: {}",
            on_disk
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn inline_plaintext_overrides_schema_encrypt() {
        // Inline @plaintext on an entry must win over a schema-owned @encrypt for the same key.
        let dir = std::env::temp_dir().join("dotsec-test-inline-plaintext-wins");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();
        let (identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();

        let schema = dotenv::parse_schema("# @encrypt\nFOO\n").unwrap();

        let lines = vec![
            Line::Directive {
                name: "plaintext".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "FOO".into(),
                value: "hello".into(),
                quote_type: QuoteType::None,
            },
            Line::Newline,
        ];

        let engine = EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(key_file),
        });
        encrypt_lines_to_sec(&lines, &sec_file, &engine, Some(&schema))
            .await
            .unwrap();

        let on_disk = std::fs::read_to_string(&sec_file).unwrap();
        assert!(
            on_disk.contains("FOO=hello"),
            "inline @plaintext should keep value plain: {}",
            on_disk
        );
        assert!(
            !on_disk.contains("FOO=ENC["),
            "inline @plaintext was ignored: {}",
            on_disk
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- write_sec_file safety ---

    #[test]
    #[cfg(unix)]
    fn write_sec_file_refuses_to_follow_symlink_to_existing_file() {
        // Layout: .sec.key is a symlink to ~/.ssh/id_rsa (mocked here as `target`).
        // write_sec_file(".sec.key", "new content") must NOT overwrite target.
        let dir = std::env::temp_dir().join("dotsec-test-symlink-refuse");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        let link = dir.join("link.sec");
        std::fs::write(&target, "do-not-touch").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = write_sec_file(link.to_str().unwrap(), "new content");
        assert!(result.is_err(), "writing through symlink must error");
        assert!(
            result.unwrap_err().to_string().contains("symlink"),
            "error should mention symlink"
        );

        let target_after = std::fs::read_to_string(&target).unwrap();
        assert_eq!(target_after, "do-not-touch", "symlink target was clobbered");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_sec_file_creates_new_file_atomically() {
        let dir = std::env::temp_dir().join("dotsec-test-write-create");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fresh.sec");

        write_sec_file(path.to_str().unwrap(), "hello").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello");

        // No stray temp files left behind in the directory.
        let strays: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name();
                let n = n.to_string_lossy();
                n.starts_with(".fresh.sec.tmp.")
            })
            .collect();
        assert!(strays.is_empty(), "leftover temp files: {:?}", strays);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_sec_file_overwrites_existing_regular_file() {
        let dir = std::env::temp_dir().join("dotsec-test-write-overwrite");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("existing.sec");
        std::fs::write(&path, "old").unwrap();

        write_sec_file(path.to_str().unwrap(), "new").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");

        // Confirm we replaced the file (not the symlink-target attack — the original
        // wasn't a symlink, so direct overwrite is the correct behavior).
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert!(meta.file_type().is_file());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- v3 attack-scenario regression tests ---
    //
    // These map to the threats the v3 file MAC is designed to defeat. Each one
    // produces a v3 file via the normal encrypt path, mutates it in some way an
    // attacker could attempt, and asserts that the next decrypt fails with the
    // MAC-mismatch error message. Tests cover the refined MAC scope (entry
    // names + directives + ENC[…] bytes + schema hash; plaintext values are
    // intentionally NOT covered, see `plaintext_value_change_preserves_mac`
    // in crypto/src/mac.rs for the dev-loop UX promise).

    /// Generate a fresh test fixture directory + matching .sec.key.
    fn v3_fixture_dir(name: &str) -> (String, String, String) {
        let dir = std::env::temp_dir().join(format!("dotsec-test-v3-{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sec_file = dir.join("test.sec").to_string_lossy().to_string();
        let key_file = dir.join("test.sec.key").to_string_lossy().to_string();
        let (identity, _) = crypto::local::generate_keypair();
        std::fs::write(&key_file, &identity).unwrap();
        (dir.to_string_lossy().to_string(), sec_file, key_file)
    }

    fn v3_local_engine(key_file: &str) -> EncryptionEngine {
        EncryptionEngine::Local(LocalEncryptionOptions {
            key_file: Some(key_file.to_string()),
        })
    }

    /// Encrypt the given lines into a v3 .sec file under `sec_file`. No schema.
    async fn v3_encrypt(lines: &[Line], sec_file: &str, key_file: &str) {
        let engine = v3_local_engine(key_file);
        encrypt_lines_to_sec(lines, sec_file, &engine, None)
            .await
            .unwrap();
    }

    /// Same, but with an explicit schema. Schema hash gets derived inside
    /// the encrypt path so tests don't have to manage hash plumbing.
    async fn v3_encrypt_with_schema(
        lines: &[Line],
        sec_file: &str,
        key_file: &str,
        schema: &dotenv::Schema,
    ) {
        let engine = v3_local_engine(key_file);
        encrypt_lines_to_sec(lines, sec_file, &engine, Some(schema))
            .await
            .unwrap();
    }

    fn assert_mac_mismatch_error(err: &dyn std::error::Error) {
        let msg = err.to_string();
        // Asserts the contract of MAC_FAILURE_MESSAGE rather than its literal
        // text. Two signal phrases must survive any future rewording:
        // - the "in a way dotsec can't verify" framing tells the user this is
        //   an integrity failure, not a decryption failure;
        // - "dotsec encrypt" must appear as the recovery command.
        assert!(
            msg.contains("dotsec can't verify"),
            "MAC-failure copy must explain integrity-verification failed: {}",
            msg
        );
        assert!(
            msg.contains("dotsec encrypt"),
            "MAC-failure copy must surface the recovery command: {}",
            msg
        );
    }

    #[tokio::test]
    async fn v3_push_directive_tamper_fails_mac() {
        // Attack 1: attacker rewrites @push to redirect a secret to their own SSM path.
        let (_dir, sec_file, key_file) = v3_fixture_dir("push-tamper");

        let lines = vec![
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Directive {
                name: "push".into(),
                value: Some("aws-ssm(path=\"/legit\")".into()),
            },
            Line::Newline,
            Line::Kv {
                key: "DB_PASSWORD".into(),
                value: "hunter2".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];
        v3_encrypt(&lines, &sec_file, &key_file).await;

        // Mutate @push value in place on disk.
        let on_disk = std::fs::read_to_string(&sec_file).unwrap();
        let tampered = on_disk.replace("/legit", "/attacker-owned");
        std::fs::write(&sec_file, tampered).unwrap();

        let result = decrypt_sec_to_lines(
            &sec_file,
            &v3_local_engine(&key_file),
            &crypto::mac::empty_schema_hash(),
        )
        .await;
        match result {
            Err(e) => assert_mac_mismatch_error(e.as_ref()),
            Ok(_) => panic!("MAC verification must reject @push directive tampering"),
        }
    }

    #[tokio::test]
    async fn v3_keyid_tamper_blocks_decrypt() {
        // Attack 2 (adapted for local provider): attacker swaps @key-id.
        // Reaches the same end goal — MAC failure before any provider call.
        let (_dir, sec_file, key_file) = v3_fixture_dir("keyid-tamper");

        let lines = vec![
            Line::Directive {
                name: "key-id".into(),
                value: Some("alias/legit".into()),
            },
            Line::Newline,
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "API_KEY".into(),
                value: "sk-test-123".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];
        v3_encrypt(&lines, &sec_file, &key_file).await;

        let on_disk = std::fs::read_to_string(&sec_file).unwrap();
        let tampered = on_disk.replace("alias/legit", "alias/attacker");
        std::fs::write(&sec_file, tampered).unwrap();

        let result = decrypt_sec_to_lines(
            &sec_file,
            &v3_local_engine(&key_file),
            &crypto::mac::empty_schema_hash(),
        )
        .await;
        match result {
            Err(e) => assert_mac_mismatch_error(e.as_ref()),
            Ok(_) => panic!("MAC verification must reject @key-id tampering"),
        }
    }

    #[tokio::test]
    async fn v3_type_directive_tamper_fails_mac() {
        // Attack 3: attacker weakens @type to bypass validation.
        let (_dir, sec_file, key_file) = v3_fixture_dir("type-tamper");

        let lines = vec![
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Directive {
                name: "type".into(),
                value: Some("enum(\"prod\",\"staging\")".into()),
            },
            Line::Newline,
            Line::Kv {
                key: "ENV".into(),
                value: "prod".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];
        v3_encrypt(&lines, &sec_file, &key_file).await;

        let on_disk = std::fs::read_to_string(&sec_file).unwrap();
        // Replace the enum with a permissive string type.
        let tampered = on_disk.replace("@type=enum(\"prod\",\"staging\")", "@type=string");
        std::fs::write(&sec_file, tampered).unwrap();

        let result = decrypt_sec_to_lines(
            &sec_file,
            &v3_local_engine(&key_file),
            &crypto::mac::empty_schema_hash(),
        )
        .await;
        match result {
            Err(e) => assert_mac_mismatch_error(e.as_ref()),
            Ok(_) => panic!("MAC verification must reject @type directive tampering"),
        }
    }

    #[tokio::test]
    async fn v3_enc_value_rollback_fails_mac() {
        // Attack 4: attacker keeps the key name but swaps in an older ENC[…]
        // ciphertext (e.g. from a git history). AAD binds ciphertext to key
        // name, not to time — MAC over ENC[…] bytes is what catches the swap.
        let (_dir, sec_file, key_file) = v3_fixture_dir("enc-rollback");

        let lines_v1 = vec![
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "DB_PASSWORD".into(),
                value: "old-password".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];
        v3_encrypt(&lines_v1, &sec_file, &key_file).await;
        let v1_on_disk = std::fs::read_to_string(&sec_file).unwrap();
        // Extract the old ENC[…] ciphertext for later rollback.
        let old_enc = v1_on_disk
            .lines()
            .find(|l| l.starts_with("DB_PASSWORD="))
            .unwrap()
            .to_string();

        // Now write a new value — same key name, different ciphertext.
        let lines_v2 = vec![
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "DB_PASSWORD".into(),
                value: "new-password".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];
        v3_encrypt(&lines_v2, &sec_file, &key_file).await;

        // Attacker rolls back: substitute the OLD ENC[…] line back in.
        let v2_on_disk = std::fs::read_to_string(&sec_file).unwrap();
        let tampered = v2_on_disk
            .lines()
            .map(|l| {
                if l.starts_with("DB_PASSWORD=") {
                    old_enc.as_str()
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&sec_file, format!("{}\n", tampered)).unwrap();

        let result = decrypt_sec_to_lines(
            &sec_file,
            &v3_local_engine(&key_file),
            &crypto::mac::empty_schema_hash(),
        )
        .await;
        match result {
            Err(e) => assert_mac_mismatch_error(e.as_ref()),
            Ok(_) => panic!("MAC verification must reject ENC[…] rollback"),
        }
    }

    #[tokio::test]
    async fn v3_manual_reorder_fails_mac() {
        // Attack 5: attacker reorders entries by hand without re-MACing.
        // Entry order is in the canonical bytes, so reorder flips the MAC.
        let (_dir, sec_file, key_file) = v3_fixture_dir("reorder");

        let lines = vec![
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "ALPHA".into(),
                value: "a".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "BETA".into(),
                value: "b".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];
        v3_encrypt(&lines, &sec_file, &key_file).await;

        let on_disk = std::fs::read_to_string(&sec_file).unwrap();
        let parsed = dotenv::parse_dotenv(&on_disk).unwrap();
        // Swap the two ENC[…] Kv lines in-place — they end up with each other's key name.
        let alpha_idx = parsed
            .iter()
            .position(|l| matches!(l, Line::Kv { key, .. } if key == "ALPHA"))
            .unwrap();
        let beta_idx = parsed
            .iter()
            .position(|l| matches!(l, Line::Kv { key, .. } if key == "BETA"))
            .unwrap();
        let mut swapped = parsed.clone();
        swapped.swap(alpha_idx, beta_idx);
        std::fs::write(&sec_file, dotenv::lines_to_string(&swapped)).unwrap();

        let result = decrypt_sec_to_lines(
            &sec_file,
            &v3_local_engine(&key_file),
            &crypto::mac::empty_schema_hash(),
        )
        .await;
        match result {
            Err(e) => {
                // Two possible failures: AEAD trips first (key-name AAD mismatch)
                // or MAC trips first (entry order changed). Both prove the
                // tamper was caught — accept either.
                let msg = e.to_string();
                assert!(
                    msg.contains("dotsec can't verify")
                        || msg.contains("encryption failed")
                        || msg.contains("commitment"),
                    "reorder must be caught by MAC or per-value AEAD: {}",
                    msg
                );
            }
            Ok(_) => panic!("entry reorder must be caught (MAC or AEAD)"),
        }
    }

    #[tokio::test]
    async fn v3_schema_tamper_invalidates_file_mac() {
        // Attack 6: attacker mutates the active schema (e.g. drops @max=65535
        // to disable validation). The .sec file's MAC was computed against a
        // particular schema_hash; if the schema changes semantically, the
        // hash changes and the MAC fails on the next load.
        let (_dir, sec_file, key_file) = v3_fixture_dir("schema-tamper");

        let original_schema = dotenv::parse_schema("# @type=number @max=65535\nPORT\n").unwrap();

        let lines = vec![
            Line::Kv {
                key: "PORT".into(),
                value: "8080".into(),
                quote_type: QuoteType::None,
            },
            Line::Newline,
        ];
        v3_encrypt_with_schema(&lines, &sec_file, &key_file, &original_schema).await;

        // Attacker drops @max — schema canonical bytes differ → hash differs.
        let tampered_schema = dotenv::parse_schema("# @type=number\nPORT\n").unwrap();
        let tampered_hash =
            crypto::mac::schema_hash(Some(&dotenv::schema_to_canonical_bytes(&tampered_schema)));

        let result =
            decrypt_sec_to_lines(&sec_file, &v3_local_engine(&key_file), &tampered_hash).await;
        match result {
            Err(e) => assert_mac_mismatch_error(e.as_ref()),
            Ok(_) => panic!("schema tamper must invalidate the file MAC"),
        }
    }

    #[tokio::test]
    async fn v3_plaintext_value_edit_does_not_break_run() {
        // The dev-loop UX promise: hand-edit a plaintext value, run should still
        // succeed. Counterpart to the security tests above — proves the MAC
        // scope is tight enough to allow legitimate edits.
        let (_dir, sec_file, key_file) = v3_fixture_dir("plaintext-edit");

        let lines = vec![
            Line::Kv {
                key: "PORT".into(),
                value: "3000".into(),
                quote_type: QuoteType::None,
            },
            Line::Newline,
        ];
        v3_encrypt(&lines, &sec_file, &key_file).await;

        let on_disk = std::fs::read_to_string(&sec_file).unwrap();
        std::fs::write(&sec_file, on_disk.replace("PORT=3000", "PORT=4000")).unwrap();

        let decrypted = decrypt_sec_to_lines(
            &sec_file,
            &v3_local_engine(&key_file),
            &crypto::mac::empty_schema_hash(),
        )
        .await
        .expect("plaintext edit must not invalidate MAC");
        let port_val = decrypted.iter().find_map(|l| match l {
            Line::Kv { key, value, .. } if key == "PORT" => Some(value.clone()),
            _ => None,
        });
        assert_eq!(port_val.as_deref(), Some("4000"));
    }

    #[tokio::test]
    async fn v3_plaintext_entry_addition_trips_mac() {
        // Inject-protection regression: hand-adding a new plaintext entry
        // (the canonical attack `EXFIL_URL=https://attacker.example`) MUST
        // trip the MAC. Users who legitimately want to add by hand are
        // pointed at `dotsec encrypt` via the error message.
        let (_dir, sec_file, key_file) = v3_fixture_dir("plaintext-add");

        let lines = vec![
            Line::Kv {
                key: "PORT".into(),
                value: "3000".into(),
                quote_type: QuoteType::None,
            },
            Line::Newline,
        ];
        v3_encrypt(&lines, &sec_file, &key_file).await;

        let on_disk = std::fs::read_to_string(&sec_file).unwrap();
        let tampered = format!("{}EXFIL_URL=https://attacker.example\n", on_disk);
        std::fs::write(&sec_file, tampered).unwrap();

        let result = decrypt_sec_to_lines(
            &sec_file,
            &v3_local_engine(&key_file),
            &crypto::mac::empty_schema_hash(),
        )
        .await;
        match result {
            Err(e) => assert_mac_mismatch_error(e.as_ref()),
            Ok(_) => panic!("plaintext-entry injection must trip the MAC"),
        }
    }

    #[tokio::test]
    async fn v3_plaintext_entry_injection_at_start_trips_mac() {
        // Sibling of the previous test: injecting BEFORE the @provider line
        // exercises a different parse path. `extract_file_config` stops at
        // the first Kv, so an injected Kv at line 1 displaces the original
        // file-level directives in the canonical's `file-directive:` block
        // AND adds a new entry name. Either change is enough to trip MAC.
        let (_dir, sec_file, key_file) = v3_fixture_dir("plaintext-add-at-start");

        let lines = vec![
            Line::Directive {
                name: "provider".into(),
                value: Some("local".into()),
            },
            Line::Newline,
            Line::Kv {
                key: "PORT".into(),
                value: "3000".into(),
                quote_type: QuoteType::None,
            },
            Line::Newline,
        ];
        v3_encrypt(&lines, &sec_file, &key_file).await;

        let on_disk = std::fs::read_to_string(&sec_file).unwrap();
        // Find the first directive line, inject right before it.
        let injected = on_disk.replacen("# @provider", "EXFIL=stolen\n# @provider", 1);
        std::fs::write(&sec_file, injected).unwrap();

        let result = decrypt_sec_to_lines(
            &sec_file,
            &v3_local_engine(&key_file),
            &crypto::mac::empty_schema_hash(),
        )
        .await;
        match result {
            Err(e) => assert_mac_mismatch_error(e.as_ref()),
            Ok(_) => panic!("injection before file-level directives must trip the MAC"),
        }
    }

    // --- M1: `dotsec encrypt` recovery command ---

    #[tokio::test]
    async fn dotsec_encrypt_re_macs_after_directive_edit() {
        // Tampering scenario the user can fix: flip @encrypt → @plaintext on
        // disk (legitimate edit if they want to expose a previously-secret
        // value), then run `dotsec encrypt` to re-MAC. Resulting file must
        // decrypt cleanly and the value must reflect the new directive.
        let (_dir, sec_file, key_file) = v3_fixture_dir("encrypt-recovery");
        let engine = v3_local_engine(&key_file);

        let lines = vec![
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "API_KEY".into(),
                value: "sk-test-original".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];
        v3_encrypt(&lines, &sec_file, &key_file).await;

        // Tamper: @encrypt → @plaintext.
        let on_disk = std::fs::read_to_string(&sec_file).unwrap();
        std::fs::write(&sec_file, on_disk.replace("@encrypt", "@plaintext")).unwrap();

        // First confirm the MAC fails as expected.
        let fail =
            decrypt_sec_to_lines(&sec_file, &engine, &crypto::mac::empty_schema_hash()).await;
        assert!(fail.is_err(), "MAC must fail before re-encrypt");

        // Simulate `dotsec encrypt`: decrypt with MAC bypass, re-encrypt.
        let bypassed = decrypt_sec_to_lines_for_remac_only(&sec_file, &engine)
            .await
            .expect("AEAD must still authenticate ciphertexts on the bypass path");
        encrypt_lines_to_sec(&bypassed, &sec_file, &engine, None)
            .await
            .expect("re-encrypt with new MAC must succeed");

        // Now the file decrypts cleanly and API_KEY is plaintext per the new directive.
        let decrypted = decrypt_sec_to_lines(&sec_file, &engine, &crypto::mac::empty_schema_hash())
            .await
            .expect("decrypt after re-encrypt must succeed");
        let api_val = decrypted.iter().find_map(|l| match l {
            Line::Kv { key, value, .. } if key == "API_KEY" => Some(value.clone()),
            _ => None,
        });
        assert_eq!(api_val.as_deref(), Some("sk-test-original"));

        // And the on-disk value is no longer ENC[…] — per the new @plaintext.
        let final_on_disk = std::fs::read_to_string(&sec_file).unwrap();
        assert!(
            !final_on_disk.contains("ENC["),
            "value should be plaintext after re-encrypt under @plaintext: {final_on_disk}"
        );
    }

    #[tokio::test]
    async fn dotsec_encrypt_aead_still_authenticates_on_bypass() {
        // The "MAC bypass is safe because per-value AEAD" contract. Flip a bit
        // inside an ENC[…] payload — the unverified-decrypt path must still
        // fail, otherwise the bypass would be a true integrity bypass.
        let (_dir, sec_file, key_file) = v3_fixture_dir("encrypt-aead-still");
        let engine = v3_local_engine(&key_file);

        let lines = vec![
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Newline,
            Line::Kv {
                key: "API_KEY".into(),
                value: "sk-original".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];
        v3_encrypt(&lines, &sec_file, &key_file).await;

        // Corrupt one base64 char inside the ENC[…] payload.
        let on_disk = std::fs::read_to_string(&sec_file).unwrap();
        let corrupted = on_disk.replacen("ENC[", "ENC[AA", 1);
        std::fs::write(&sec_file, corrupted).unwrap();

        let result = decrypt_sec_to_lines_for_remac_only(&sec_file, &engine).await;
        assert!(
            result.is_err(),
            "bypass path must still trip per-value AEAD on corrupted ciphertext"
        );
    }

    // --- M3: rotate-key v3 emission + schema-only @encrypt preserved ---

    #[tokio::test]
    async fn rotate_key_emits_v3_and_preserves_schema_only_encrypt() {
        // Combined regression for the original v3 emit + CR4 (schema-only
        // @encrypt must NOT be rotated as plaintext). We can't drive the
        // rotate-key command directly from here (it lives in dotsec/), so we
        // simulate its full pipeline: decrypt, generate new DEK, merge schema
        // directives, re-encrypt, build v3 header.
        let (_dir, sec_file, key_file) = v3_fixture_dir("rotate-key-schema");
        let engine = v3_local_engine(&key_file);
        let schema = dotenv::parse_schema("# @encrypt\nSECRET\n").unwrap();

        // Encrypt with schema-only @encrypt (no inline directive).
        let lines = vec![
            Line::Kv {
                key: "SECRET".into(),
                value: "hunter2".into(),
                quote_type: QuoteType::Double,
            },
            Line::Newline,
        ];
        v3_encrypt_with_schema(&lines, &sec_file, &key_file, &schema).await;

        let original_on_disk = std::fs::read_to_string(&sec_file).unwrap();
        assert!(
            original_on_disk.contains("SECRET=\"ENC["),
            "schema-only @encrypt should produce ENC[…] on first encrypt"
        );

        // Decrypt (with schema applied) to get plaintext lines.
        let schema_hash =
            crypto::mac::schema_hash(Some(&dotenv::schema_to_canonical_bytes(&schema)));
        let plaintext_lines = decrypt_sec_to_lines(&sec_file, &engine, &schema_hash)
            .await
            .unwrap();

        // Simulate rotate-key: generate new DEK, re-encrypt with the same
        // schema applied (which is what the fixed rotate-key now does).
        encrypt_lines_to_sec(&plaintext_lines, &sec_file, &engine, Some(&schema))
            .await
            .unwrap();

        let after_on_disk = std::fs::read_to_string(&sec_file).unwrap();
        assert!(
            after_on_disk.contains("SECRET=\"ENC["),
            "rotate-key must keep schema-only @encrypt values encrypted (CR4): {after_on_disk}"
        );
        assert!(
            !after_on_disk.contains("hunter2"),
            "plaintext must never appear on disk after rotate-key: {after_on_disk}"
        );

        // Final round-trip — schema-bound MAC verifies, value recovers.
        let final_decrypt = decrypt_sec_to_lines(&sec_file, &engine, &schema_hash)
            .await
            .unwrap();
        let secret = final_decrypt.iter().find_map(|l| match l {
            Line::Kv { key, value, .. } if key == "SECRET" => Some(value.clone()),
            _ => None,
        });
        assert_eq!(secret.as_deref(), Some("hunter2"));
    }

    // --- M5: select_target_format direct tests ---
    //
    // Pins down the "no silent format bumps" policy. The function reads the
    // bytes that are actually on disk — not the post-decrypt lines a caller
    // might pass — so v2/v3 round-trips through any command preserve format.

    fn select_format_fixture(name: &str, body: &str) -> String {
        let dir = std::env::temp_dir().join(format!("dotsec-test-select-format-{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.sec").to_string_lossy().to_string();
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn select_target_format_v3_header_returns_recognized() {
        let path =
            select_format_fixture("v3", "# @dotsec(format=v3, mac=AA==, dek=AQ==)\nFOO=bar\n");
        assert_eq!(select_target_format(&path), SecFormat::Recognized);
    }

    #[test]
    fn select_target_format_empty_file_returns_none() {
        // A non-existent or empty file is "new" — the encrypt path then
        // defaults to v3.
        let path = select_format_fixture("empty", "");
        assert_eq!(select_target_format(&path), SecFormat::None);
    }

    #[test]
    fn select_target_format_no_envelope_returns_none() {
        // A plaintext-only .env-ish file with no v1/v2/v3 markers.
        let path = select_format_fixture("plain", "FOO=bar\nBAR=baz\n");
        assert_eq!(select_target_format(&path), SecFormat::None);
    }

    #[test]
    fn select_target_format_missing_file_returns_none() {
        // Caller hands us a path that doesn't exist (new file scenario).
        assert_eq!(
            select_target_format("/nonexistent/path/that/should/not/exist.sec"),
            SecFormat::None
        );
    }

    #[test]
    fn select_target_format_unparseable_returns_unparseable() {
        // A half-edited v2 file with a syntax error must NOT be treated as
        // "new file → v3 by default" — silently bumping the format would
        // overwrite the user's in-progress edit with v3 and lose the v2
        // bytes. The encrypt path turns Unparseable into a hard error.
        let path = select_format_fixture(
            "unparseable",
            // Stray quoted bare line that the dotenv parser will reject.
            "this is not =parseable=\nKv missing\n",
        );
        assert_eq!(select_target_format(&path), SecFormat::Unparseable);
    }

    // --- M2: upgrade-format v2 → v3 round-trip ---

    // --- MAC-failure diagnostic against git HEAD ---

    use std::process::{Command, Stdio};

    fn git_init_repo(dir: &Path) {
        let ok = Command::new("git")
            .args(["init", "-q", "-b", "main"])
            .current_dir(dir)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            // Older git without -b: fall back.
            let _ = Command::new("git")
                .args(["init", "-q"])
                .current_dir(dir)
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .stdout(Stdio::null())
                .status();
        }
        for (k, v) in [
            ("user.email", "test@example.com"),
            ("user.name", "Test"),
            ("commit.gpgsign", "false"),
        ] {
            let _ = Command::new("git")
                .args(["config", k, v])
                .current_dir(dir)
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .stdout(Stdio::null())
                .status();
        }
    }

    fn git_commit_all(dir: &Path) {
        let _ = Command::new("git")
            .args(["add", "-A"])
            .current_dir(dir)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .status();
        let _ = Command::new("git")
            .args(["commit", "-q", "-m", "snap"])
            .current_dir(dir)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .status();
    }

    fn write(p: &Path, content: &str) {
        std::fs::write(p, content).unwrap();
    }

    fn fixture_sec() -> &'static str {
        "# dotsec v7.0.0 — encrypted environment file\n\
         # @dotsec(format=v3, mac=irrelevant, dek=irrelevant)\n\
         # @provider=local @default-encrypt\n\
         FOO=\"ENC[abc]\"\n\
         BAR=\"ENC[def]\"\n"
    }

    #[test]
    fn diagnose_returns_none_outside_git_repo() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(".sec");
        write(&p, fixture_sec());
        let out = diagnose_mac_drift_against_git_head(p.to_str().unwrap());
        assert!(
            out.is_none(),
            "expected None outside a git repo, got {:?}",
            out
        );
    }

    #[test]
    fn diagnose_returns_none_when_file_untracked() {
        let dir = tempfile::tempdir().unwrap();
        git_init_repo(dir.path());
        // make initial commit so HEAD exists
        write(&dir.path().join("README"), "x");
        git_commit_all(dir.path());

        let p = dir.path().join(".sec");
        write(&p, fixture_sec());
        let out = diagnose_mac_drift_against_git_head(p.to_str().unwrap());
        assert!(out.is_none(), "expected None for untracked file");
    }

    #[test]
    fn diagnose_detects_added_entry() {
        let dir = tempfile::tempdir().unwrap();
        git_init_repo(dir.path());
        let p = dir.path().join(".sec");
        write(&p, fixture_sec());
        git_commit_all(dir.path());

        // Add a new entry.
        let mut tampered = String::from(fixture_sec());
        tampered.push_str("BAZ=\"ENC[xyz]\"\n");
        write(&p, &tampered);

        let report = diagnose_mac_drift_against_git_head(p.to_str().unwrap())
            .expect("diagnostic should produce output");
        assert!(report.contains("entry added: BAZ"), "report:\n{report}");
    }

    #[test]
    fn diagnose_detects_removed_entry() {
        let dir = tempfile::tempdir().unwrap();
        git_init_repo(dir.path());
        let p = dir.path().join(".sec");
        write(&p, fixture_sec());
        git_commit_all(dir.path());

        // Remove BAR.
        let tampered = fixture_sec().replace("BAR=\"ENC[def]\"\n", "");
        write(&p, &tampered);

        let report = diagnose_mac_drift_against_git_head(p.to_str().unwrap())
            .expect("diagnostic should produce output");
        assert!(report.contains("entry removed: BAR"), "report:\n{report}");
    }

    #[test]
    fn diagnose_detects_changed_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        git_init_repo(dir.path());
        let p = dir.path().join(".sec");
        write(&p, fixture_sec());
        git_commit_all(dir.path());

        // Mutate FOO's ciphertext.
        let tampered = fixture_sec().replace("FOO=\"ENC[abc]\"", "FOO=\"ENC[ZZZ]\"");
        write(&p, &tampered);

        let report = diagnose_mac_drift_against_git_head(p.to_str().unwrap())
            .expect("diagnostic should produce output");
        assert!(
            report.contains("ENC[\u{2026}] value of FOO changed"),
            "report:\n{report}"
        );
    }

    #[test]
    fn diagnose_detects_per_entry_directive_change() {
        let dir = tempfile::tempdir().unwrap();
        git_init_repo(dir.path());
        let p = dir.path().join(".sec");
        let original = "# dotsec v7.0.0\n\
                        # @dotsec(format=v3, mac=x, dek=x)\n\
                        # @type=string\n\
                        FOO=\"hello\"\n";
        write(&p, original);
        git_commit_all(dir.path());

        let tampered = "# dotsec v7.0.0\n\
                        # @dotsec(format=v3, mac=x, dek=x)\n\
                        # @type=number\n\
                        FOO=\"hello\"\n";
        write(&p, tampered);

        let report = diagnose_mac_drift_against_git_head(p.to_str().unwrap())
            .expect("diagnostic should produce output");
        assert!(
            report.contains("directives on FOO changed"),
            "report:\n{report}"
        );
        assert!(report.contains("@type=string"), "report:\n{report}");
        assert!(report.contains("@type=number"), "report:\n{report}");
    }

    #[test]
    fn diagnose_detects_file_level_directive_change() {
        let dir = tempfile::tempdir().unwrap();
        git_init_repo(dir.path());
        let p = dir.path().join(".sec");
        write(&p, fixture_sec());
        git_commit_all(dir.path());

        let tampered = fixture_sec().replace("@provider=local", "@provider=aws");
        write(&p, &tampered);

        let report = diagnose_mac_drift_against_git_head(p.to_str().unwrap())
            .expect("diagnostic should produce output");
        assert!(
            report.contains("file-level directive changed"),
            "report:\n{report}"
        );
    }

    #[test]
    fn diagnose_reports_schema_when_no_per_entry_drift() {
        let dir = tempfile::tempdir().unwrap();
        git_init_repo(dir.path());
        let p = dir.path().join(".sec");
        write(&p, fixture_sec());
        git_commit_all(dir.path());

        // Don't touch .sec at all — file matches HEAD bit-for-bit, but
        // MAC still failed (in real life that means schema_hash changed).
        let report = diagnose_mac_drift_against_git_head(p.to_str().unwrap())
            .expect("diagnostic should produce output");
        assert!(
            report.contains("schema referenced when encrypting has changed"),
            "report:\n{report}"
        );
    }
}
