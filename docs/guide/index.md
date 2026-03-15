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

Parse a `.env` file into structured entries with their directives:

```js
import { parse } from '@dotsec/core';
import { readFileSync } from 'node:fs';

const source = readFileSync('.env', 'utf8');
const entries = parse(source);

for (const entry of entries) {
  console.log(`${entry.key} = ${entry.value}`);
  if (entry.directives.length > 0) {
    console.log(`  directives:`, entry.directives.map(d => d.name));
  }
}
```

Validate directives and values — catches unknown directives, type mismatches, and invalid push targets:

```js
import { validate } from '@dotsec/core';

const errors = validate(source);
for (const err of errors) {
  console.error(`${err.key}: ${err.message}`);
}
```

Convert to JSON or roundtrip-format back to `.env`:

```js
import { toJson, format } from '@dotsec/core';

const json = toJson(source);       // '[{"FOO":"bar"},{"PORT":"3000"}]'
const formatted = format(source);  // normalized .env output
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

Add `dotsec-core` as a dependency:

```toml
[dependencies]
dotsec-core = "5"
```

Parse a `.env` file and inspect entries with their directives:

```rust
use dotsec_core::dotenv::{parse_dotenv, lines_to_entries, validate_entries};

let content = std::fs::read_to_string(".env").unwrap();
let lines = parse_dotenv(&content).unwrap();
let entries = lines_to_entries(&lines);

for entry in &entries {
    println!("{} = {} (encrypt: {})", entry.key, entry.value, entry.has_directive("encrypt"));
}

let errors = validate_entries(&entries);
for err in &errors {
    eprintln!("{}: {}", err.key, err.message);
}
```

Encrypt a `.env` file into a `.sec` file using AWS KMS:

```rust
use dotsec_core::{load_file, parse_content, encrypt_lines_to_sec};
use dotsec_core::{EncryptionEngine, AwsEncryptionOptions};

let content = load_file(".env").unwrap();
let lines = parse_content(&content).unwrap();
encrypt_lines_to_sec(&lines, ".sec", &EncryptionEngine::Aws(AwsEncryptionOptions {
    key_id: Some("alias/dotsec".into()),
    region: Some("eu-west-1".into()),
})).await.unwrap();
```

Decrypt a `.sec` file, resolve interpolation, and redact secrets from output:

```rust
use dotsec_core::{decrypt_sec_to_lines, resolve_env_vars, collect_secret_values, redact};

let lines = decrypt_sec_to_lines(".sec", &engine).await.unwrap();
let env_vars = resolve_env_vars(&lines);
let secrets = collect_secret_values(&lines, &env_vars);

let safe_output = redact("my password is s3cret", &secrets);
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
dotsec-core/             Core library (encryption, decryption, interpolation, redaction)
dotsec/                  CLI binary crate (uses dotsec-core)
  npm/                   npm distribution packages (CLI)
dotsec-napi/             Native Node.js bindings (uses dotsec-core, published as @dotsec/core)
  npm/                   npm distribution packages (library)
dotenv/                  .env/.sec parser (internal, re-exported by dotsec-core)
aws/                     AWS KMS encryption (internal)
```
