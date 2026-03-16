# Getting Started

dotsec encrypts your `.env` files into `.sec` files using AWS KMS. The `.sec` file is committed to git as the single source of truth for your secrets — no more sharing credentials over Slack or managing secret vaults.

## Install

:::tabs

@tab npm

```bash
npm install -g dotsec
```

@tab cargo

```bash
cargo install dotsec
```

@tab npx

```bash
npx dotsec init
```

:::

## Quick start

```bash
dotsec init                              # set up AWS KMS key
dotsec set API_KEY sk-live-xxx --encrypt # add a secret
dotsec import                            # migrate existing .env → .sec
dotsec run -- node server.js             # run with decrypted env vars
```

That's it. Your `.sec` file goes into git, your `.env` stays in `.gitignore`.

## Core workflow

```
.env (plaintext, gitignored)          .sec (encrypted, committed)
┌─────────────────────────┐           ┌──────────────────────────┐
│ DATABASE_URL=postgres://│  encrypt  │ DATABASE_URL=ENC[base64] │
│ API_KEY=sk-live-xxx     │ ───────▶  │ API_KEY=ENC[base64]      │
│ DEBUG=true              │           │ DEBUG=true                │
└─────────────────────────┘           │ __DOTSEC_KEY__="wrapped" │
                                 ◀─── └──────────────────────────┘
                                decrypt
```

Each secret is encrypted individually with AES-256-GCM using a local data key (DEK) wrapped by KMS. This makes `.sec` files git-mergeable — changing one secret only affects that line.

```bash
dotsec import              # .env → .sec (encrypts values marked with @encrypt)
dotsec export              # .sec → .env (decrypts)
dotsec show                # display decrypted .sec contents
dotsec validate            # check directives and values
dotsec diff .env .env.staging  # compare env files
dotsec run -- npm start    # inject decrypted vars into a command
```

## Library

### Node.js — `@dotsec/core`

Native bindings for parsing, validating, and formatting `.env` files:

```bash
npm install @dotsec/core
```

```js
import { parse, validate, toJson, format } from '@dotsec/core';
import { readFileSync } from 'node:fs';

const source = readFileSync('.env', 'utf8');

// Parse into structured entries
const entries = parse(source);
for (const entry of entries) {
  console.log(`${entry.key} = ${entry.value}`);
}

// Validate directives
const errors = validate(source);
for (const err of errors) {
  console.error(`${err.key}: ${err.message}`);
}

// Convert to JSON or normalize formatting
const json = toJson(source);
const formatted = format(source);
```

### Rust — `dotsec-core`

```toml
[dependencies]
dotsec-core = "5"
```

```rust
use dotsec_core::dotenv::{parse_dotenv, lines_to_entries, validate_entries};

let content = std::fs::read_to_string(".env").unwrap();
let lines = parse_dotenv(&content).unwrap();
let entries = lines_to_entries(&lines);

for entry in &entries {
    println!("{} = {}", entry.key, entry.value);
}

let errors = validate_entries(&entries);
for err in &errors {
    eprintln!("{}: {}", err.key, err.message);
}
```

Encrypt and decrypt with AWS KMS:

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

## Channels

| Channel | npm | Cargo |
|---------|-----|-------|
| Stable | `npm install dotsec` | `cargo install dotsec` |
| Beta | `npm install dotsec@beta` | — |

## Project structure

```
dotsec-core/       Core library (encryption, decryption, interpolation, redaction)
dotsec/            CLI binary (uses dotsec-core)
  npm/             npm platform packages
dotsec-napi/       Node.js bindings (published as @dotsec/core)
  npm/             npm platform packages
dotenv/            .env/.sec parser (internal)
aws/               AWS KMS encryption (internal)
```
