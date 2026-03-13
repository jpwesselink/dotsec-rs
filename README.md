# dotsec

Encrypt and manage `.env` files with AWS KMS envelope encryption.

`.env` is plaintext, `.sec` is its encrypted counterpart — committed to git as the single source of truth for secrets.

## Install

```bash
# npm
npm install -g dotsec

# cargo
cargo install dotsec
```

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

## Commands

### `dotsec init`

Interactive setup that creates a `.sec` file with encryption config:

1. Prompts for provider, KMS key ID, region
2. Asks encrypt-all or encrypt-none default
3. Writes config as directives at the top of `.sec`

### `dotsec set`

Add or update a single variable. Interactive mode prompts for encryption, type, and push target. Non-interactive mode uses flags:

```bash
dotsec set                                    # fully interactive
dotsec set DB_URL postgres://... --encrypt    # inline with flag
dotsec set PORT 3000 --type number            # with type directive
```

Plaintext variables are written directly — no KMS round trip. Encrypted variables trigger decrypt → modify → re-encrypt.

### `dotsec import`

Migrate a `.env` file into `.sec`. Walks through each variable prompting for encryption, type, and push targets.

```bash
dotsec import                  # import from .env (default)
dotsec import .env.production  # import from specific file
```

If `.sec` already exists, offers: import new variables only, overwrite all, or cancel. Source `.env` directives pre-populate the prompts as defaults.

If `.sec` doesn't exist, prompts for encryption config (like `init`).

### `dotsec export`

Decrypt `.sec` and write to `.env`:

```bash
dotsec export              # decrypt .sec → stdout
dotsec export -o .env      # decrypt .sec → .env file
```

### `dotsec show`

Display decrypted `.sec` contents in various formats:

```bash
dotsec show              # raw key=value
dotsec show --json       # JSON object
dotsec show --csv        # CSV format
dotsec show --table      # formatted table
```

### `dotsec run`

Decrypt `.sec` in memory, resolve `${VAR}` interpolation, inject env vars into a child process. Encrypted values are automatically redacted from stdout/stderr.

```bash
dotsec run -- node server.js
dotsec run --using env -- cargo test    # use .env instead of .sec
```

The child process runs in a pseudo-terminal (PTY), so colors, interactive output, and `isatty()` detection work automatically.

### `dotsec validate`

Check directives and values against type constraints:

```bash
dotsec validate                 # validate .env
dotsec validate --using sec     # decrypt and validate .sec
```

Validates: unknown directives, type mismatches (number, boolean, enum membership), missing directive values, and shell environment overrides.

### `dotsec diff`

Compare environment files for structural differences:

```bash
dotsec diff --base .env .env.staging .env.production
dotsec diff --base .env .env.staging --values  # include value diffs
```

Reports: missing keys, extra keys, directive mismatches, ordering differences, and optionally value differences.

## Directives

Directives are comments that control encryption, typing, and push targets:

```bash
# @provider=aws @key-id=alias/dotsec @region=us-east-1 @default-encrypt

# @encrypt
# @type=string
# @push=aws-ssm(path="/myapp/prod/db-url")
DATABASE_URL="postgres://user:pass@localhost:5432/mydb"

# @plaintext
# @type=enum("development", "preview", "production")
NODE_ENV="production"

# @plaintext
# @type=number
PORT=3000
```

### Available directives

| Directive | Value | Description |
|-----------|-------|-------------|
| `@provider` | `aws` | Encryption provider (file-level) |
| `@key-id` | KMS key ID or alias | KMS key to use (file-level) |
| `@region` | AWS region | AWS region (file-level) |
| `@default-encrypt` | none | Encrypt all variables by default (file-level) |
| `@default-plaintext` | none | Don't encrypt by default (file-level) |
| `@encrypt` | none | Mark variable for encryption |
| `@plaintext` | none | Exclude from encryption (overrides file-level default) |
| `@type` | `string`, `number`, `boolean`, `enum("a", "b")` | Type validation |
| `@push` | `aws-ssm(...)`, `aws-secrets-manager(...)` | Push targets |

File-level directives (`@provider`, `@key-id`, `@region`, `@default-encrypt`/`@default-plaintext`) go at the top of the file. Per-variable `@encrypt`/`@plaintext` always overrides the file-level default.

### Push target syntax

```bash
# Simple
# @push=aws-ssm

# With parameters (values must be quoted)
# @push=aws-ssm(path="/myapp/prod", prefix="/app")

# Multiple targets
# @push=aws-ssm(path="/myapp/prod"), aws-secrets-manager(path="/myapp/prod/db")
```

## How encryption works

1. Parse `.sec`, find entries with `@encrypt` (or file-level `@default-encrypt`)
2. Generate a random 64-char hex ID for each encrypted value
3. Replace encrypted values with their IDs in the `.sec` output
4. Build a `{id: real_value}` map, serialize to JSON
5. Encrypt the JSON blob using AWS KMS envelope encryption (AES-256-GCM + KMS data key wrapping)
6. Append as `__DOTSEC__="<base64>"` to the `.sec` file

Re-encrypting reuses IDs for unchanged values — only modified secrets get new IDs, keeping git diffs minimal.

## Variable interpolation

`${VAR}` references are resolved at runtime by `dotsec run`. Single-quoted values are not interpolated (bash convention).

```bash
# @type=string
BASE_URL="https://api.example.com"

# @type=string
WEBHOOK_URL="${BASE_URL}/webhooks"
```

## Configuration

All configuration lives in the `.sec` file itself as directives — no external config file needed:

```bash
# @provider=aws @key-id=alias/dotsec @region=us-east-1 @default-encrypt

DATABASE_URL="postgres://..."
API_KEY="sk-..."
```

Use `--sec-file` to specify a different `.sec` file:

```bash
dotsec --sec-file .sec.production show
```

## npm packages

| Package | Description |
|---------|-------------|
| `dotsec` | CLI binary (platform-specific via `optionalDependencies`) |
| `@dotsec/core` | NAPI-RS bindings for programmatic use (planned) |
| `@dotsec/config` | Drop-in `dotenv/config` replacement — `import '@dotsec/config'` (planned) |

## Roadmap

- **`dotsec push`** — push values to AWS SSM Parameter Store and/or Secrets Manager based on `@push` directives
- **`@dotsec/core`** — NAPI-RS native Node.js module exposing encrypt/decrypt/resolve programmatically
- **`@dotsec/config`** — drop-in replacement for `dotenv/config` that reads `.sec` and decrypts transparently
- **TypeScript type generation** — generate `env.d.ts` from `@type` directives
- **Additional providers** — public-key encryption (no cloud dependency), GCP KMS, Azure Key Vault
