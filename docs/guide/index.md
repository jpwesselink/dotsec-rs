# Getting Started

`.env` is plaintext, `.sec` is its encrypted counterpart — committed to git as the single source of truth for secrets.

## Node.js

### CLI

```bash
npm install -g dotsec

# or use directly
npx dotsec init
```

### Channels

| Channel | Version | Install |
|---------|---------|---------|
| `latest` | `5.0.0` | `npm install dotsec` |
| `beta` | `5.0.0-beta.abc1234` | `npm install dotsec@beta` |
| `pr-N` | `5.0.0-pr-42.abc1234` | `npm install dotsec@pr-42` |

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
  npm/                   npm distribution packages
    dotsec/              meta-package (optionalDependencies)
    dotsec-darwin-arm64/ platform binaries
    dotsec-darwin-x64/
    dotsec-linux-arm64-gnu/
    dotsec-linux-x64-gnu/
    dotsec-win32-arm64-msvc/
    dotsec-win32-x64-msvc/
dotenv/                  .env/.sec parser (internal)
aws/                     AWS KMS encryption (internal)
```
