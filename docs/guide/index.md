# Getting Started

`.env` is plaintext, `.sec` is its encrypted counterpart — committed to git as the single source of truth for secrets.

## Node.js

### CLI

```bash
npm install -g dotsec

# or use directly
npx dotsec init
```

### Library

Native Node.js bindings for parsing, validating, and formatting `.env` files:

```bash
npm install @dotsec/core
```

```js
import { parse, validate, toJson, format } from '@dotsec/core';

const entries = parse('# @encrypt\nDB_URL="postgres://localhost"\nDEBUG=true\n');
// [{ key: "DB_URL", value: "postgres://localhost", quoteType: "Double", directives: [{ name: "encrypt" }] }, ...]

const errors = validate('# @bogus\nFOO="bar"\n');
// [{ key: "FOO", message: "unknown directive @bogus..." }]

const json = toJson('FOO=bar\nBAZ=123\n');
// '[{"FOO":"bar"},{"BAZ":"123"}]'

const formatted = format('FOO=bar\n');
// 'FOO=bar\n'
```

### Channels

| Channel | Version | Install |
|---------|---------|---------|
| `latest` | `5.0.0` | `npm install dotsec` |
| `beta` | `5.0.0-beta.abc1234` | `npm install dotsec@beta` |

## Rust

### CLI

```bash
cargo install dotsec
```

### Library

Add `dotsec` as a dependency:

```toml
[dependencies]
dotsec = { version = "5", features = ["library"] }
```

```rust
use dotenv::{parse_dotenv, lines_to_entries, validate_entries};

// Parse a .env file
let content = std::fs::read_to_string(".env").unwrap();
let lines = parse_dotenv(&content).unwrap();

// Get structured entries with directives
let entries = lines_to_entries(&lines);
for entry in &entries {
    println!("{} = {} (encrypt: {})", entry.key, entry.value, entry.has_directive("encrypt"));
}

// Validate directives and values
let errors = validate_entries(&entries);
for err in &errors {
    eprintln!("{}: {}", err.key, err.message);
}
```

```rust
use dotsec::{load_file, parse_content, encrypt_lines_to_sec, EncryptionEngine};

// Load, parse, and encrypt
let content = load_file(".env").unwrap();
let lines = parse_content(&content).unwrap();
encrypt_lines_to_sec(&lines, ".sec", &EncryptionEngine::Aws {
    key_id: "alias/dotsec".into(),
    region: "eu-west-1".into(),
}).await.unwrap();
```

### Channels

| Channel | Version | Install |
|---------|---------|---------|
| crates.io | `5.0.0` | `cargo install dotsec` |

## Quick start

```bash
dotsec init                          # set up encryption config
dotsec set                           # add a variable interactively
dotsec set API_KEY sk-live-xxx --encrypt  # add inline
dotsec import                        # migrate .env → .sec
dotsec export                        # .sec → .env (decrypts)
dotsec show                          # show decrypted .sec contents
dotsec run -- node server.js         # run with decrypted env vars
dotsec validate                      # check directives and values
dotsec diff --base .env .env.staging # compare env files
```

## Project structure

```
dotsec/                  CLI binary crate
  npm/                   npm distribution packages (CLI)
dotsec-napi/             Native Node.js bindings (@dotsec/core)
  npm/                   npm distribution packages (library)
dotenv/                  .env/.sec parser (internal)
aws/                     AWS KMS encryption (internal)
```
