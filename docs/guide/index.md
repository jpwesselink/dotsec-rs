# Getting Started

`.env` is plaintext, `.sec` is its encrypted counterpart — committed to git as the single source of truth for secrets.

## Install

```bash
# stable
npm install -g dotsec

# beta (latest from main)
npm install -g dotsec@beta

# cargo
cargo install dotsec
```

| Channel | Trigger | Version | Install |
|---------|---------|---------|---------|
| `latest` | Release PR merge | `5.0.0` | `npm install dotsec` |
| `beta` | Every commit on `main` | `5.0.0-beta.abc1234` | `npm install dotsec@beta` |
| `pr-N` | Every commit on a PR | `5.0.0-pr-42.abc1234` | `npm install dotsec@pr-42` |
| crates.io | Release PR merge | `5.0.0` | `cargo install dotsec` |

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

## npm packages

| Package | Description |
|---------|-------------|
| `dotsec` | CLI binary (platform-specific via `optionalDependencies`) |
| `@dotsec/core` | NAPI-RS bindings for programmatic use (planned) |
| `@dotsec/config` | Drop-in `dotenv/config` replacement — `import '@dotsec/config'` (planned) |
