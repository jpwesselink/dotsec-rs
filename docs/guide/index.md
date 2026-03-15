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
npm install @jpwesselink/dotsec-core
```

```js
import { parse, validate, toJson, format } from '@jpwesselink/dotsec-core';

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
use dotsec;

// Parse and decrypt a .sec file
// See the dotsec crate docs for full API
```

The `dotenv` and `aws` crates are internal and not published separately.

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
dotsec-napi/             Native Node.js bindings (@jpwesselink/dotsec-core)
  npm/                   npm distribution packages (library)
dotenv/                  .env/.sec parser (internal)
aws/                     AWS KMS encryption (internal)
```
