use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, ContentArrangement, Table,
};
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
) -> Result<String, Box<dyn std::error::Error>> {
    let lines = decrypt_sec_to_lines(sec_file, encryption_engine).await?;
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
            dotenv::Line::Kv(key, value, qt) => {
                let masked = if value.chars().count() > 4 {
                    format!("{}****", value.chars().take(4).collect::<String>())
                } else {
                    "****".to_string()
                };
                dotenv::Line::Kv(key.clone(), masked, qt.clone())
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
                    Line::Kv(key, value, _) => Some(format!("{key}={value}")),
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
                if let Line::Kv(var_name, var_value, _) = line {
                    table.add_row(vec![var_name, var_value]);
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

        // Maximum length of any secret — used as overlap window to catch
        // secrets that straddle read-chunk boundaries.
        let max_secret_len = secrets_clone.iter().map(|s| s.len()).max().unwrap_or(0);

        // Tracks how many bytes at the front of `remainder` were already
        // written to stdout (the overlap from the previous iteration).
        let mut already_written: usize = 0;

        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    remainder.extend_from_slice(&buf[..n]);

                    // Process all complete lines
                    let mut lines_end: usize = 0;
                    {
                        let mut search_from = 0;
                        while let Some(pos) = remainder[search_from..].iter().position(|&b| b == b'\n') {
                            lines_end = search_from + pos + 1;
                            search_from = lines_end;
                        }
                    }

                    if lines_end > 0 {
                        // Redact the full block including overlap from
                        // previous iteration, so secrets spanning the
                        // boundary are caught.
                        let block = String::from_utf8_lossy(&remainder[..lines_end]);
                        let redacted = redact(&block, &secrets_clone);

                        // Redaction replaces secrets with same-length masks,
                        // so byte positions are stable. Only emit the portion
                        // after what was already written.
                        let redacted_bytes = redacted.as_bytes();
                        let skip = already_written.min(redacted_bytes.len());
                        let keep = max_secret_len.min(lines_end);
                        let emit_end = redacted_bytes.len().saturating_sub(keep);
                        if emit_end > skip {
                            let _ = stdout.write_all(&redacted_bytes[skip..emit_end]);
                        }

                        let drain_up_to = lines_end - keep;
                        remainder.drain(..drain_up_to);
                        already_written = keep;
                    }
                    let _ = stdout.flush();
                }
                Err(e) => {
                    eprintln!("warning: PTY read error: {}", e);
                    break;
                }
            }
        }
        // Flush remaining partial line (including any overlap)
        if !remainder.is_empty() {
            let line = String::from_utf8_lossy(&remainder);
            let redacted = redact(&line, &secrets_clone);
            let redacted_bytes = redacted.as_bytes();
            let skip = already_written.min(redacted_bytes.len());
            let _ = stdout.write_all(&redacted_bytes[skip..]);
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
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
        if ret == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
            return Some((ws.ws_col, ws.ws_row));
        }
    }
    None
}
