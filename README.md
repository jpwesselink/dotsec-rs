# dotsec

[![npm](https://img.shields.io/npm/v/dotsec)](https://www.npmjs.com/package/dotsec)
[![CI](https://github.com/jpwesselink/dotsec-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/jpwesselink/dotsec-rs/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**No more .env files.**

dotsec encrypts your secrets into a `.sec` file — same shape as `.env`, committed to git, decrypted in memory when your app runs. Your code still reads `process.env.X`, but there's no plaintext secrets file on disk for compromised dependencies to grep.

- **KMS-native, AWS-integrated** — `EncryptionContext` binding on every wrap and unwrap; IAM controls access, CloudTrail logs every decrypt. Push to SSM Parameter Store and Secrets Manager via `@push=aws-ssm` / `@push=aws-secrets-manager` directives, for runtime services that read from AWS directly.
- **Built like crypto matters** — AAD-bound per-value AEAD, file-level MAC over canonical content, schema-hash binding, key commitment, zeroize on every exit path, constant-time integrity checks, cargo-fuzz harness with 4 targets.
- **Schema-driven validation** with `@type`, `@format`, `@pattern`, `@min/@max`, `@enum`. Generate a zero-runtime-dependency TypeScript validator from your schema in one command.
- **Works with anything** — `dotsec run -- <your command>`. No SDK per language. Node, Python, Ruby, Go, Rust, Docker, kubectl, terraform — anything that reads env vars.
- **Standard age envelope** — no lock-in. Anyone with the private key can decrypt with the `age` or `rage` CLI directly.

## Install

```bash
npm install -g dotsec
```

Distribution is npm-only (the obvious crate names on crates.io are owned by unrelated projects, so dotsec ships as a binary inside the npm package). See [setup](https://jpwesselink.github.io/dotsec-rs/guide/setup) for `npx` and dev-dependency install patterns.

## Quick start

```bash
dotsec set API_KEY sk-live-xxx --encrypt   # creates .sec + keypair on first run
dotsec set PORT 3000                       # plaintext variable
dotsec run -- node server.js               # inject decrypted vars into your process
```

That's it. `.sec` goes into git. `.sec.key` stays out — `dotsec set`/`init` auto-adds `*.key` to `.gitignore` on first run (`--no-gitignore` to skip).

No AWS account. No config file. No setup step.

## How it works

```
.env (plaintext, gitignored)         .sec (encrypted, committed)
┌─────────────────────────┐         ┌────────────────────────────┐
│ DATABASE_URL=postgres://│ encrypt │ # @dotsec(format=v3,       │
│ API_KEY=sk-live-xxx     │ ──────▶ │ #   mac=..., dek=...)      │
│ PORT=3000               │         │ DATABASE_URL=ENC[base64]   │
└─────────────────────────┘         │ API_KEY=ENC[base64]        │
                              ◀──── │ PORT=3000                  │
                             decrypt└────────────────────────────┘
```

Each secret is encrypted individually with AES-256-GCM using a data encryption key (DEK). The DEK is wrapped by your age keypair and stored in the `.sec` file. This makes `.sec` files git-mergeable — changing one secret only affects that line.

## Common commands

```bash
dotsec set KEY value --encrypt     # add/update an encrypted variable
dotsec set KEY value               # add/update a plaintext variable
dotsec import                      # .env → .sec (interactive)
dotsec import -y                   # .env → .sec (auto-detect types)
dotsec run -- <command>            # run with decrypted env vars
dotsec show                        # display decrypted .sec (values masked)
dotsec show --reveal               # display decrypted .sec (plaintext)
dotsec export -o .env              # .sec → .env
dotsec validate                    # check types and constraints
dotsec extract-schema              # extract directives → dotsec.schema
dotsec schema export --format ts   # generate TypeScript types from schema
dotsec rotate-key                  # generate new DEK, re-encrypt all values
```

## Team sharing

Share `.sec.key` over a secure channel (1Password, Bitwarden, etc.). For CI/CD:

```bash
export DOTSEC_PRIVATE_KEY="AGE-SECRET-KEY-1..."
```

## AWS KMS

For teams needing IAM-controlled access and CloudTrail audit logs:

```bash
dotsec init   # choose "aws", enter KMS key ID and region
```

## Project structure

```
dotsec-core/       Core library (encryption, decryption, interpolation, redaction)
dotsec/            CLI binary
  npm/             npm platform packages
dotsec-napi/       Node.js bindings (published as @dotsec/core)
  npm/             npm platform packages
dotenv/            .env/.sec parser (internal)
crypto/            Shared cryptography + local age encryption (internal)
aws/               AWS KMS encryption (internal)
```

## npm packages

| Package | Description |
|---------|-------------|
| `dotsec` | CLI binary |
| `@dotsec/core` | Native Node.js bindings for parsing, validating, and formatting |

## Release channels

| Channel | Trigger | Install |
|---------|---------|---------|
| `latest` | Release PR merge | `npm install dotsec` |
| `beta` | Every commit on `main` | `npm install dotsec@beta` |
| `<branch-slug>` | Every PR commit | `npm install dotsec@<branch-slug>` |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build/test instructions, the fuzzing harness, the LocalStack KMS integration test, and the release workflow.

---

**[Full documentation →](https://jpwesselink.github.io/dotsec-rs)**
