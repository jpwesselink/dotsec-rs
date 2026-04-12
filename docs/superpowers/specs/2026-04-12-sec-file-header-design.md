# .sec file header — design spec

## Problem

A developer opening a `.sec` file for the first time sees what looks like a normal `.env` file with cryptic comments (`# @encrypt`, `# @type=string`). Nothing identifies it as a dotsec file or tells them where to learn more. The directive-as-comment syntax is invisible to newcomers.

## Solution

A two-line comment header stamped at the top of `.sec` files, identifying the file format and linking to documentation.

```bash
# dotsec v5 — encrypted environment file
# https://github.com/jpwesselink/dotsec-rs#getting-started
```

The header is plain comments — no grammar changes, no special `Line` variants. Standard `.env` parsers ignore it.

## Header content

Exactly two comment lines followed by a blank line:

1. `# dotsec v5 — encrypted environment file` — identifies the format and version
2. `# https://github.com/jpwesselink/dotsec-rs#getting-started` — links to docs

The version (`v5`) is the major version of the dotsec format. A blank line separates the header from the rest of the file.

## API

Two functions in `dotsec-core/src/lib.rs`:

### `generate_header() -> Vec<Line>`

Returns the header as a vector of `Line` values:

```rust
pub fn generate_header() -> Vec<Line> {
    vec![
        Line::Comment { text: "# dotsec v5 — encrypted environment file".into() },
        Line::Newline,
        Line::Comment { text: "# https://github.com/jpwesselink/dotsec-rs#getting-started".into() },
        Line::Newline,
    ]
}
```

### `has_header(lines: &[Line]) -> bool`

Checks whether the header is already present:

```rust
pub fn has_header(lines: &[Line]) -> bool {
    lines.iter().any(|line| {
        matches!(line, Line::Comment { text } if text.starts_with("# dotsec v"))
    })
}
```

No version parsing, no semantic meaning — just "is the marker there?"

## CLI

### Automatic stamping (new files only)

Three commands prepend the header when creating a new `.sec` file:

- **`dotsec init`** — prepends header before config directives
- **`dotsec import`** — prepends header when creating a new `.sec` (not when appending to an existing one)
- **`dotsec migrate`** — prepends header before config directives

These commands call `generate_header()` unconditionally since they always create new files.

### `dotsec header` command (existing files)

Adds or updates the header on an existing `.sec` file. Behavior:

- If `has_header()` is true: replace the existing header lines (first two comment lines matching the pattern) with the current version
- If `has_header()` is false: prepend the header before existing content
- Idempotent — running it twice produces the same result
- Respects `--sec-file` flag for custom file paths

No automatic header insertion on commands that modify existing files (`set`, `format`, `eject`, `rotate-key`, `remove-directives`). The header is opt-in for existing files.

## NAPI bindings

Two functions exposed in `dotsec-napi/src/lib.rs`:

```typescript
generateHeader(): string
hasHeader(source: string): boolean
```

Thin wrappers: `generateHeader` calls `generate_header()` and serializes to string via `lines_to_string`. `hasHeader` parses the source, calls `has_header()`.

## File layout after header

```bash
# dotsec v5 — encrypted environment file
# https://github.com/jpwesselink/dotsec-rs#getting-started

# @provider=aws @key-id=alias/dotsec @region=us-east-1 @default-encrypt

# @encrypt @type=string
API_KEY="ENC[...]"

# @plaintext @type=number
PORT=3000

# do not edit the line below, it is managed by dotsec
__DOTSEC_KEY__="base64-wrapped-dek..."
```

## Constraints

- .env compatibility: the header is plain comments, ignored by all standard `.env` parsers
- No grammar changes, no new `Line` enum variants
- No special parser treatment — the header is regular `Line::Comment` values
- Version string is the format version (`v5`), not the crate version

## Testing

- `generate_header()` returns expected lines
- `has_header()` returns true when header present, false when absent
- `has_header()` matches any `# dotsec v` prefix (future version compatibility)
- `dotsec header` is idempotent (run twice, same result)
- `dotsec header` on a file without header prepends correctly
- `dotsec header` on a file with outdated header updates correctly
- Init/import/migrate output includes header as first lines
- NAPI `generateHeader()` returns correct string
- NAPI `hasHeader()` detects presence/absence correctly
