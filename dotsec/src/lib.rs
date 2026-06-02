use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, ContentArrangement, Table};
use dotenv::{lines_to_json, Line};

// Re-export everything from dotsec-core
pub use dotsec_core::*;

mod cli_configuration;
pub use cli_configuration::OutputFormat;

// --- Show ---

pub async fn show(
    sec_file: &str,
    encryption_engine: &EncryptionEngine,
    output_format: &OutputFormat,
    reveal: bool,
    schema_hash: &[u8; 32],
) -> Result<String, Box<dyn std::error::Error>> {
    let lines = decrypt_sec_to_lines(sec_file, encryption_engine, schema_hash).await?;
    if reveal {
        create_output(&lines, output_format)
    } else {
        let masked = mask_all_values(&lines);
        create_output(&masked, output_format)
    }
}

/// Mask all key-value line values: show first 4 chars followed by `****`.
/// Since dotsec is a security tool, default to hiding values unless `--reveal` is passed.
fn mask_all_values(lines: &[dotenv::Line]) -> Vec<dotenv::Line> {
    lines
        .iter()
        .map(|line| match line {
            dotenv::Line::Kv {
                key,
                value,
                quote_type,
            } => {
                let masked = if value.chars().count() > 4 {
                    format!("{}****", value.chars().take(4).collect::<String>())
                } else {
                    "****".to_string()
                };
                dotenv::Line::Kv {
                    key: key.clone(),
                    value: masked,
                    quote_type: quote_type.clone(),
                }
            }
            other => other.clone(),
        })
        .collect()
}

fn create_output(
    lines: &[Line],
    output_format: &OutputFormat,
) -> Result<String, Box<dyn std::error::Error>> {
    match output_format {
        OutputFormat::Raw => {
            let lines_string = lines
                .iter()
                .filter_map(|line| match line {
                    Line::Kv { key, value, .. } => Some(format!("{key}={value}")),
                    _ => None,
                })
                .collect::<Vec<String>>()
                .join("\n");
            Ok(lines_string)
        }
        OutputFormat::Text => {
            let mut table = Table::new();
            table
                .load_preset(UTF8_FULL)
                .apply_modifier(UTF8_ROUND_CORNERS)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["Key", "Value"]);
            for line in lines {
                if let Line::Kv { key, value, .. } = line {
                    table.add_row(vec![key, value]);
                }
            }
            Ok(format!("{table}"))
        }
        OutputFormat::Json => {
            let json = lines_to_json(lines)?;
            Ok(json)
        }
        OutputFormat::Csv => {
            let csv = dotenv::lines_to_csv(lines)?;
            Ok(csv)
        }
    }
}

// --- Run ---

/// Mask any prefix of `buf` that matches a non-empty suffix of one of the known secrets.
///
/// The PTY redaction loop holds back the last `max_secret_len` bytes after each emit so a
/// chunk-spanning secret can be detected on the next iteration. When a secret happens to
/// straddle a chunk boundary, its head is emitted as asterisks in iteration N and the tail
/// sits at the start of iteration N+1's buffer as raw bytes. The full secret is no longer
/// present in the buffer at that point so `redact` can't find it. This helper closes the
/// hole by masking the longest secret-suffix that appears at the start of the buffer.
///
/// Trade-off: may over-mask if non-secret output coincidentally begins with bytes that
/// match a secret suffix. For typical (long, random-looking) secret values the collision
/// rate is negligible.
fn mask_secret_suffix_at_start(buf: &mut String, secrets: &[String]) {
    let mut best_match_len = 0;
    for secret in secrets {
        let max_len = secret.len().min(buf.len());
        for len in (1..=max_len).rev() {
            if len <= best_match_len {
                break;
            }
            let suffix = &secret.as_bytes()[secret.len() - len..];
            if buf.as_bytes().starts_with(suffix) {
                best_match_len = len;
                break;
            }
        }
    }
    if best_match_len > 0 {
        let mask: String = "*".repeat(best_match_len);
        buf.replace_range(..best_match_len, &mask);
    }
}

/// Spawn a child process in a PTY with env vars injected.
/// Redacts secret values from output. Colors and interactive features work
/// because the child sees a real terminal.
/// Returns the exit code.
pub async fn run_command(
    cmd_parts: &[String],
    env_vars: &[(String, String)],
    secrets: &[String],
) -> Result<i32, Box<dyn std::error::Error>> {
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    use std::io::{Read, Write};
    // `Arc` is only used by the Unix-gated SIGWINCH handler below — Windows
    // doesn't subscribe to that signal, so the import would be flagged
    // unused on `cargo build --target *-windows-msvc` without this gate.
    #[cfg(unix)]
    use std::sync::Arc;

    let (cols, rows) = terminal_size().unwrap_or((80, 24));

    let pty_system = native_pty_system();
    let pair = pty_system.openpty(PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    })?;

    let mut cmd = CommandBuilder::new(&cmd_parts[0]);
    for arg in &cmd_parts[1..] {
        cmd.arg(arg);
    }
    for (key, val) in env_vars {
        cmd.env(key, val);
    }
    // portable-pty does NOT inherit the parent process's cwd by default —
    // unset, the spawned shell lands in the user's home directory. Pin it
    // explicitly so `dotsec run -- pwd` reports the directory the user
    // invoked dotsec from. Failure to read cwd is treated as fatal because
    // every reasonable command needs one.
    if let Ok(cwd) = std::env::current_dir() {
        cmd.cwd(cwd);
    }

    let mut child = pair.slave.spawn_command(cmd)?;
    drop(pair.slave);

    let reader = pair.master.try_clone_reader()?;

    // SIGWINCH forwarding — resize PTY when parent terminal is resized
    #[cfg(unix)]
    let _sigwinch_guard = {
        use std::sync::atomic::{AtomicBool, Ordering};

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);

        let master = pair.master;
        let handle = std::thread::spawn(move || {
            use signal_hook::iterator::Signals;
            let mut signals = match Signals::new([signal_hook::consts::SIGWINCH]) {
                Ok(s) => s,
                Err(_) => return,
            };
            for _ in signals.forever() {
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                if let Some((cols, rows)) = terminal_size() {
                    let _ = master.resize(PtySize {
                        rows,
                        cols,
                        pixel_width: 0,
                        pixel_height: 0,
                    });
                }
            }
        });
        (stop, handle)
    };
    let secrets_clone = secrets.to_vec();

    // Read PTY output in chunks, split on newlines for redaction.
    //
    // To catch secrets that span across line-read boundaries, we keep an
    // overlap of `max_secret_len` bytes from the previous batch in the
    // remainder buffer and only output up to the non-overlapping portion.
    //
    // Limitation: multi-line secrets (containing literal newlines) are NOT
    // redacted because redaction operates on single lines. This is a
    // best-effort approach.
    let read_task = tokio::task::spawn_blocking(move || {
        let mut reader = std::io::BufReader::new(reader);
        let mut stdout = std::io::stdout();
        let mut remainder = Vec::new();
        let mut buf = [0u8; 4096];

        // Maximum length of any secret — kept in `remainder` as an overlap window
        // so secrets that straddle a chunk boundary can still be redacted by the
        // next iteration's pass.
        let max_secret_len = secrets_clone.iter().map(|s| s.len()).max().unwrap_or(0);

        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    remainder.extend_from_slice(&buf[..n]);

                    // Locate the byte just past the last complete line in the buffer.
                    let lines_end = match remainder.iter().rposition(|&b| b == b'\n') {
                        Some(pos) => pos + 1,
                        None => 0,
                    };

                    if lines_end > 0 {
                        let block = String::from_utf8_lossy(&remainder[..lines_end]);
                        let mut redacted = redact(&block, &secrets_clone);
                        // If the previous iteration emitted the head of a chunk-spanning
                        // secret as asterisks, this iteration's `redacted` starts with the
                        // tail of that secret as raw bytes (the full secret isn't present
                        // in the overlap-only context, so `redact` can't see it). Mask any
                        // leading suffix-of-a-secret to plug that hole.
                        mask_secret_suffix_at_start(&mut redacted, &secrets_clone);
                        let redacted_bytes = redacted.as_bytes();

                        // Hold back the last `keep` bytes — they may be the start of a
                        // secret whose tail arrives in the next chunk. They stay in
                        // `remainder` and get a second redaction pass before being emitted.
                        let keep = max_secret_len.min(lines_end);
                        let emit_end = redacted_bytes.len().saturating_sub(keep);
                        let _ = stdout.write_all(&redacted_bytes[..emit_end]);
                        let _ = stdout.flush();

                        remainder.drain(..emit_end);
                    }
                }
                Err(e) => {
                    eprintln!("warning: PTY read error: {}", e);
                    break;
                }
            }
        }
        // PTY closed — flush any held-back overlap plus the trailing partial line.
        if !remainder.is_empty() {
            let tail = String::from_utf8_lossy(&remainder);
            let mut redacted = redact(&tail, &secrets_clone);
            mask_secret_suffix_at_start(&mut redacted, &secrets_clone);
            let _ = stdout.write_all(redacted.as_bytes());
            let _ = stdout.flush();
        }
    });

    let exit = child.wait()?;
    if let Err(e) = read_task.await {
        eprintln!("warning: output reader task failed: {}", e);
    }

    // Stop the SIGWINCH handler thread
    #[cfg(unix)]
    {
        let (stop, _handle) = _sigwinch_guard;
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        // Send ourselves SIGWINCH to unblock the signal iterator
        // SAFETY: libc::raise is async-signal-safe and only delivers SIGWINCH to the
        // current process. We previously installed the SIGWINCH handler ourselves
        // (via signal-hook), so the signal cannot have an unintended effect.
        unsafe {
            libc::raise(libc::SIGWINCH);
        }
    }

    Ok(exit.exit_code() as i32)
}

/// Get the current terminal size (cols, rows).
fn terminal_size() -> Option<(u16, u16)> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        return None;
    }
    #[cfg(unix)]
    {
        // SAFETY: libc::winsize is a POD struct of integers; an all-zero bit pattern
        // is a valid value. The ioctl below populates the struct on success.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: STDOUT_FILENO is always a valid file descriptor for the running
        // process. TIOCGWINSZ writes a winsize through the pointer we provide; we
        // pass a valid &mut to a stack-allocated winsize. Failure (non-tty stdout,
        // EINVAL, etc.) returns non-zero and we discard the struct below.
        let ret = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
        if ret == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
            return Some((ws.ws_col, ws.ws_row));
        }
    }
    None
}

/// Mask all values in a list of lines for safe display.
///
/// For `Line::Kv` items:
///   - Values with fewer than 4 characters → `"****"`
///   - Values with 4 or more characters → first 4 characters + `"****"`
///
#[cfg(test)]
mod tests {
    use super::*;
    use dotenv::{Line, QuoteType};

    // --- mask_all_values ---

    #[test]
    fn mask_short_value_becomes_stars() {
        let lines = vec![Line::Kv {
            key: "K".into(),
            value: "abc".into(),
            quote_type: QuoteType::Double,
        }];
        let masked = mask_all_values(&lines);
        assert_eq!(masked.len(), 1);
        if let Line::Kv { value: v, .. } = &masked[0] {
            assert_eq!(v, "****");
        } else {
            panic!("expected Kv");
        }
    }

    #[test]
    fn mask_empty_value_becomes_stars() {
        let lines = vec![Line::Kv {
            key: "K".into(),
            value: "".into(),
            quote_type: QuoteType::None,
        }];
        let masked = mask_all_values(&lines);
        if let Line::Kv { value: v, .. } = &masked[0] {
            assert_eq!(v, "****");
        } else {
            panic!("expected Kv");
        }
    }

    #[test]
    fn mask_exactly_four_chars_becomes_stars() {
        let lines = vec![Line::Kv {
            key: "K".into(),
            value: "abcd".into(),
            quote_type: QuoteType::Double,
        }];
        let masked = mask_all_values(&lines);
        if let Line::Kv { value: v, .. } = &masked[0] {
            assert_eq!(v, "****");
        } else {
            panic!("expected Kv");
        }
    }

    #[test]
    fn mask_long_value_shows_first_four_plus_stars() {
        let lines = vec![Line::Kv {
            key: "K".into(),
            value: "secret_password".into(),
            quote_type: QuoteType::Double,
        }];
        let masked = mask_all_values(&lines);
        if let Line::Kv { value: v, .. } = &masked[0] {
            assert_eq!(v, "secr****");
        } else {
            panic!("expected Kv");
        }
    }

    #[test]
    fn mask_multibyte_utf8_no_panic() {
        let lines = vec![Line::Kv {
            key: "E".into(),
            value: "\u{1F600}\u{1F601}\u{1F602}\u{1F603}\u{1F604}".into(),
            quote_type: QuoteType::Double,
        }];
        let masked = mask_all_values(&lines);
        if let Line::Kv { value: v, .. } = &masked[0] {
            assert_eq!(v, "\u{1F600}\u{1F601}\u{1F602}\u{1F603}****");
        } else {
            panic!("expected Kv");
        }
    }

    #[test]
    fn mask_multibyte_short_utf8_no_panic() {
        let lines = vec![Line::Kv {
            key: "K".into(),
            value: "\u{1F600}\u{1F601}".into(),
            quote_type: QuoteType::Double,
        }];
        let masked = mask_all_values(&lines);
        if let Line::Kv { value: v, .. } = &masked[0] {
            assert_eq!(v, "****");
        } else {
            panic!("expected Kv");
        }
    }

    #[test]
    fn mask_non_kv_lines_unchanged() {
        let lines = vec![
            Line::Comment {
                text: "# a comment".into(),
            },
            Line::Directive {
                name: "encrypt".into(),
                value: None,
            },
            Line::Newline,
            Line::Whitespace { text: "  ".into() },
        ];
        let masked = mask_all_values(&lines);
        assert_eq!(masked.len(), 4);
        assert!(matches!(&masked[0], Line::Comment { text: ref c } if c == "# a comment"));
        assert!(
            matches!(&masked[1], Line::Directive { name: ref n, value: None } if n == "encrypt")
        );
        assert!(matches!(&masked[2], Line::Newline));
        assert!(matches!(&masked[3], Line::Whitespace { text: ref w } if w == "  "));
    }

    #[test]
    fn mask_mixed_lines() {
        let lines = vec![
            Line::Comment {
                text: "# header".into(),
            },
            Line::Newline,
            Line::Kv {
                key: "SHORT".into(),
                value: "ab".into(),
                quote_type: QuoteType::None,
            },
            Line::Newline,
            Line::Kv {
                key: "LONG".into(),
                value: "abcdefgh".into(),
                quote_type: QuoteType::Double,
            },
        ];
        let masked = mask_all_values(&lines);
        assert!(matches!(&masked[0], Line::Comment { .. }));
        assert!(matches!(&masked[1], Line::Newline));
        if let Line::Kv { value: v, .. } = &masked[2] {
            assert_eq!(v, "****");
        }
        assert!(matches!(&masked[3], Line::Newline));
        if let Line::Kv { value: v, .. } = &masked[4] {
            assert_eq!(v, "abcd****");
        }
    }
}
