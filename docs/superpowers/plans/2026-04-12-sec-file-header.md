# .sec File Header Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a two-line comment header to `.sec` files that identifies the format and links to docs, improving discoverability for new users.

**Architecture:** Two functions in `dotsec-core` (`generate_header`, `has_header`), a new `dotsec header` CLI command, header prepended in `init`/`import`/`migrate`, and NAPI bindings for Node.js consumers.

**Tech Stack:** Rust, clap (CLI), napi-rs (Node bindings)

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `dotsec-core/src/lib.rs` | Modify | Add `generate_header()` and `has_header()` |
| `dotsec/src/cli/commands/header.rs` | Create | New `dotsec header` CLI command |
| `dotsec/src/cli/commands/mod.rs` | Modify | Register header module and subcommand |
| `dotsec/src/cli/mod.rs` | Modify | Wire up `header::match_args` |
| `dotsec/src/cli/commands/init.rs` | Modify | Prepend header in output |
| `dotsec/src/cli/commands/import.rs` | Modify | Prepend header when creating new `.sec` |
| `dotsec/src/cli/commands/migrate.rs` | Modify | Prepend header in output |
| `dotsec-napi/src/lib.rs` | Modify | Add `generateHeader()` and `hasHeader()` |

---

### Task 1: `generate_header` and `has_header` in dotsec-core

**Files:**
- Modify: `dotsec-core/src/lib.rs:8-31` (after `write_sec_file`, before `parse_content`)

- [ ] **Step 1: Write the failing tests**

Add to the bottom of the existing `#[cfg(test)] mod tests` block in `dotsec-core/src/lib.rs`:

```rust
    // --- header ---

    #[test]
    fn generate_header_has_two_comment_lines() {
        let header = generate_header();
        let comments: Vec<_> = header.iter().filter(|l| matches!(l, Line::Comment { .. })).collect();
        assert_eq!(comments.len(), 2);
    }

    #[test]
    fn generate_header_first_line_contains_version() {
        let header = generate_header();
        assert!(matches!(&header[0], Line::Comment { text } if text.contains("dotsec v5")));
    }

    #[test]
    fn generate_header_second_line_contains_url() {
        let header = generate_header();
        assert!(matches!(&header[2], Line::Comment { text } if text.contains("github.com/jpwesselink/dotsec-rs")));
    }

    #[test]
    fn has_header_true_when_present() {
        let lines = generate_header();
        assert!(has_header(&lines));
    }

    #[test]
    fn has_header_false_when_absent() {
        let lines = vec![
            Line::Comment { text: "# just a comment".into() },
            Line::Newline,
            Line::Kv { key: "FOO".into(), value: "bar".into(), quote_type: QuoteType::None },
        ];
        assert!(!has_header(&lines));
    }

    #[test]
    fn has_header_matches_any_version() {
        let lines = vec![
            Line::Comment { text: "# dotsec v99 — encrypted environment file".into() },
        ];
        assert!(has_header(&lines));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p dotsec-core -- header`
Expected: FAIL — `generate_header` and `has_header` not found

- [ ] **Step 3: Write the implementation**

Add after `write_sec_file` and before `parse_content` in `dotsec-core/src/lib.rs`:

```rust
// --- Header ---

/// Generate the standard dotsec file header (two comment lines + newlines).
pub fn generate_header() -> Vec<Line> {
    vec![
        Line::Comment { text: "# dotsec v5 — encrypted environment file".into() },
        Line::Newline,
        Line::Comment { text: "# https://github.com/jpwesselink/dotsec-rs#getting-started".into() },
        Line::Newline,
    ]
}

/// Check whether parsed lines contain the dotsec header.
pub fn has_header(lines: &[Line]) -> bool {
    lines.iter().any(|line| {
        matches!(line, Line::Comment { text } if text.starts_with("# dotsec v"))
    })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p dotsec-core -- header`
Expected: all 6 header tests PASS

- [ ] **Step 5: Commit**

```bash
git add dotsec-core/src/lib.rs
git commit -m "feat: add generate_header and has_header to dotsec-core"
```

---

### Task 2: `dotsec header` CLI command

**Files:**
- Create: `dotsec/src/cli/commands/header.rs`
- Modify: `dotsec/src/cli/commands/mod.rs:1-36`
- Modify: `dotsec/src/cli/mod.rs:90-104`

- [ ] **Step 1: Create `header.rs` with command definition and logic**

Create `dotsec/src/cli/commands/header.rs`:

```rust
use clap::Command;
use colored::Colorize;

use crate::default_options::DefaultOptions;

pub fn command() -> Command {
    Command::new("header")
        .about("Add or update the dotsec header in a .sec file")
}

pub async fn match_args(
    matches: &clap::ArgMatches,
    default_options: &DefaultOptions<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    if matches.subcommand_matches("header").is_none() {
        return Ok(());
    }

    let sec_file = default_options.sec_file;

    if !std::path::Path::new(sec_file).exists() {
        return Err(format!("{} not found", sec_file).into());
    }

    let content = std::fs::read_to_string(sec_file)?;
    let mut lines = dotenv::parse_dotenv(&content)?;

    if dotsec::has_header(&lines) {
        // Remove existing header lines (comments matching "# dotsec v" and the URL line + their newlines)
        let mut i = 0;
        while i < lines.len() {
            match &lines[i] {
                dotenv::Line::Comment { text } if text.starts_with("# dotsec v") => {
                    lines.remove(i);
                    // Remove trailing newline
                    if i < lines.len() && matches!(lines[i], dotenv::Line::Newline) {
                        lines.remove(i);
                    }
                }
                dotenv::Line::Comment { text } if text.contains("github.com/jpwesselink/dotsec-rs") => {
                    lines.remove(i);
                    // Remove trailing newline
                    if i < lines.len() && matches!(lines[i], dotenv::Line::Newline) {
                        lines.remove(i);
                    }
                }
                _ => i += 1,
            }
        }
    }

    // Prepend fresh header
    let mut new_lines = dotsec::generate_header();
    new_lines.push(dotenv::Line::Newline);
    new_lines.extend(lines);

    let output = dotenv::lines_to_string(&new_lines);
    dotsec::write_sec_file(sec_file, &output)?;

    eprintln!("{} Updated header in {}", "✓".green(), sec_file);

    Ok(())
}
```

- [ ] **Step 2: Register the module in `mod.rs`**

In `dotsec/src/cli/commands/mod.rs`, add `pub mod header;` after line 5 (`pub mod format;`):

```rust
pub mod header;
```

And add `.subcommand(header::command())` in `create_command()` after the `format` subcommand line:

```rust
        .subcommand(header::command())
```

- [ ] **Step 3: Wire up in `cli/mod.rs`**

In `dotsec/src/cli/mod.rs`, add the import at line 1 (add `header` to the use statement):

```rust
use self::commands::{create_command, diff, eject, export, format, header, import, init, migrate, push, remove_directives, rotate_key, run, schema, set, show, validate};
```

And add `header::match_args` call after `format::match_args` (after line 102):

```rust
    header::match_args(&matches, &default_options).await?;
```

- [ ] **Step 4: Build and verify**

Run: `cargo build -p dotsec`
Expected: compiles successfully

Run: `cargo run -p dotsec -- header --help`
Expected: shows "Add or update the dotsec header in a .sec file"

- [ ] **Step 5: Commit**

```bash
git add dotsec/src/cli/commands/header.rs dotsec/src/cli/commands/mod.rs dotsec/src/cli/mod.rs
git commit -m "feat: add dotsec header command"
```

---

### Task 3: Stamp header in `init`, `import`, and `migrate`

**Files:**
- Modify: `dotsec/src/cli/commands/init.rs:75-80`
- Modify: `dotsec/src/cli/commands/import.rs:291-299`
- Modify: `dotsec/src/cli/commands/migrate.rs:138-144`

- [ ] **Step 1: Add header to `init.rs`**

In `dotsec/src/cli/commands/init.rs`, change lines 76-77 from:

```rust
    let mut lines = helpers::build_config_directives(&config, encrypt_all);
    lines.push(dotenv::Line::Newline);
```

to:

```rust
    let mut lines = dotsec::generate_header();
    lines.push(dotenv::Line::Newline);
    lines.extend(helpers::build_config_directives(&config, encrypt_all));
    lines.push(dotenv::Line::Newline);
```

- [ ] **Step 2: Add header to `import.rs` (full import path)**

In `dotsec/src/cli/commands/import.rs`, in the full-import branch (around line 294), change:

```rust
        let mut new_lines: Vec<dotenv::Line> = Vec::new();
        let mut var_index = 0;
        let mut inserted_config = false;

        // Build config directive lines from resolved config
        let config_lines = helpers::build_config_directives(effective_config, encrypt_all);
```

to:

```rust
        let mut new_lines: Vec<dotenv::Line> = Vec::new();
        let mut var_index = 0;
        let mut inserted_config = false;

        // Header + config directive lines
        let header = dotsec::generate_header();
        let config_lines = helpers::build_config_directives(effective_config, encrypt_all);
```

Then, where `config_lines` are inserted (around lines 314-317 and 325-327), prepend the header before the config lines. Change both insertion sites from:

```rust
                        new_lines.extend(config_lines.clone());
```

to:

```rust
                        new_lines.extend(header.clone());
                        new_lines.push(dotenv::Line::Newline);
                        new_lines.extend(config_lines.clone());
```

And the fallback insertion at the bottom (around line 344-346), change:

```rust
        if !inserted_config {
            new_lines.extend(config_lines);
```

to:

```rust
        if !inserted_config {
            new_lines.extend(header);
            new_lines.push(dotenv::Line::Newline);
            new_lines.extend(config_lines);
```

- [ ] **Step 3: Add header to `migrate.rs`**

In `dotsec/src/cli/commands/migrate.rs`, change lines 140-144 from:

```rust
    let config_lines = helpers::build_config_directives(&file_config, true);
    let mut new_lines: Vec<dotenv::Line> = Vec::new();

    // File-level config directives
    new_lines.extend(config_lines);
    new_lines.push(dotenv::Line::Newline);
```

to:

```rust
    let config_lines = helpers::build_config_directives(&file_config, true);
    let mut new_lines: Vec<dotenv::Line> = Vec::new();

    // Header + file-level config directives
    new_lines.extend(dotsec::generate_header());
    new_lines.push(dotenv::Line::Newline);
    new_lines.extend(config_lines);
    new_lines.push(dotenv::Line::Newline);
```

- [ ] **Step 4: Build and test**

Run: `cargo build --workspace`
Expected: compiles successfully

Run: `cargo test --workspace`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add dotsec/src/cli/commands/init.rs dotsec/src/cli/commands/import.rs dotsec/src/cli/commands/migrate.rs
git commit -m "feat: stamp header in init, import, and migrate"
```

---

### Task 4: NAPI bindings

**Files:**
- Modify: `dotsec-napi/src/lib.rs`

- [ ] **Step 1: Add `generateHeader` and `hasHeader` NAPI functions**

Add at the end of `dotsec-napi/src/lib.rs`, before the closing of the file:

```rust
/// Generate the standard dotsec file header as a string.
#[napi]
pub fn generate_header() -> String {
    let lines = dotsec_core::generate_header();
    dotsec_core::dotenv::lines_to_string(&lines)
}

/// Check whether a .sec file source string contains the dotsec header.
#[napi]
pub fn has_header(source: String) -> napi::Result<bool> {
    let lines = dotsec_core::dotenv::parse_dotenv(&source)
        .map_err(|e| napi::Error::from_reason(format!("Parse error: {e}")))?;
    Ok(dotsec_core::has_header(&lines))
}
```

- [ ] **Step 2: Build and verify**

Run: `cargo build --workspace`
Expected: compiles successfully

Run: `cargo test --workspace`
Expected: all tests pass

- [ ] **Step 3: Commit**

```bash
git add dotsec-napi/src/lib.rs
git commit -m "feat: add generateHeader and hasHeader NAPI bindings"
```

---

### Task 5: Final verification

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `cargo test --workspace`
Expected: all tests pass (should be 288+ tests)

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: no warnings

- [ ] **Step 3: Verify CLI end-to-end**

Run: `cargo run -p dotsec -- header --help`
Expected: shows help text for header command

- [ ] **Step 4: Push**

```bash
git push origin fix/post-merge-review-findings
```
