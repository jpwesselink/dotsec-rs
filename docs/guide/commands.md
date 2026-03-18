# Commands

## `dotsec init`

Interactive setup that creates a `.sec` file with encryption config:

1. Prompts for provider, KMS key ID, region
2. Asks encrypt-all or encrypt-none default
3. Writes config as directives at the top of `.sec`

## `dotsec set`

Add or update a single variable. Interactive mode prompts for encryption, type, and push target. Non-interactive mode uses flags:

```bash
dotsec set                                    # fully interactive
dotsec set DB_URL postgres://... --encrypt    # inline with flag
dotsec set PORT 3000 --type number            # with type directive
```

Plaintext variables are written directly — no KMS round trip. Encrypted variables trigger decrypt → modify → re-encrypt.

Secret-looking variable names (containing `KEY`, `SECRET`, `PASSWORD`, `TOKEN`, etc.) automatically use masked input in interactive mode.

### Schema-aware mode

When a `dotsec.schema` file exists:

- **Existing key in schema**: only updates the value in `.sec`, no directive prompts
- **New key**: prompts for directives and writes them to `dotsec.schema` (not inline in `.sec`)
- **No schema**: current behavior (directives inline in `.sec`)

## `dotsec import`

Migrate a `.env` file into `.sec`. Walks through each variable prompting for encryption, type, and push targets.

```bash
dotsec import                  # import from .env (default)
dotsec import .env.production  # import from specific file
dotsec import -y               # auto-accept variables with heuristic type detection
```

If `.sec` already exists, offers: import new variables only, overwrite all, or cancel. Source `.env` directives pre-populate the prompts as defaults.

If `.sec` doesn't exist, prompts for encryption config (like `init`).

The `-y` flag skips per-variable prompts only (auto-detects types using heuristics). Config prompts (provider, key, region, import mode) still appear.

## `dotsec export`

Decrypt `.sec` and write to `.env`:

```bash
dotsec export              # decrypt .sec → stdout
dotsec export -o .env      # decrypt .sec → .env file
```

## `dotsec show`

Display decrypted `.sec` contents in various formats:

```bash
dotsec show              # raw key=value
dotsec show --json       # JSON object
dotsec show --csv        # CSV format
dotsec show --table      # formatted table
```

## `dotsec run`

Decrypt `.sec` in memory, resolve `${VAR}` interpolation, inject env vars into a child process. Encrypted values are automatically redacted from stdout/stderr.

```bash
dotsec run -- node server.js                        # from .sec (decrypts)
dotsec run --using env -- cargo test                # from .env (plain)
dotsec run --using env --env-file .env.local -- sh  # custom .env path
```

The child process runs in a pseudo-terminal (PTY), so colors, interactive output, and `isatty()` detection work automatically.

When using `--using env`, no `.sec` file or AWS credentials are needed — it reads the plain `.env` file directly.

## `dotsec validate`

Check directives and values against type constraints:

```bash
dotsec validate
```

Validates: type mismatches (number, boolean, enum membership), format violations (email, url, uuid, etc.), pattern mismatches, min/max range violations, min-length/max-length violations, empty values with `@not-empty`, deprecated warnings, and shell environment overrides.

### Schema validation

When a `dotsec.schema` file exists (auto-discovered or via `--schema`), validation also checks:

- Missing keys (in schema but not in `.sec`, unless `@optional`)
- Extra keys (in `.sec` but not in schema)
- Type and constraint mismatches from schema definitions
- Deprecated key warnings
- Inline directive warnings (per-key directives in `.sec` are ignored when schema exists)

```bash
dotsec validate                              # auto-discovers dotsec.schema
dotsec validate --schema ./path/to/schema    # explicit schema path
```

Errors cause exit code 1. Warnings are displayed but do not affect the exit code.

## `dotsec format`

Reorder entries in a `.sec` file to match the key ordering defined in the schema. Requires a `dotsec.schema` to exist.

```bash
dotsec format                              # format .sec to match schema order
dotsec format --sec-file staging.sec       # format a specific file
```

Keys defined in the schema are emitted in schema order. Keys not in the schema are appended at the end. File-level directives and header comments are preserved. Handles encrypted files (decrypt → reorder → re-encrypt).

## `dotsec diff`

Compare `.sec` files for structural differences. Auto-selects the most recently modified file as the reference:

```bash
dotsec diff .sec.staging                  # compare default .sec vs .sec.staging
dotsec diff .sec.staging .sec.production  # compare all three (default .sec included)
dotsec diff --values .sec.staging         # include value differences
```

Reports: missing keys, extra keys, directive mismatches, ordering differences, and optionally value differences.

## `dotsec eject`

Extract per-key directives from a `.sec` file into a `dotsec.schema` file. This is the migration path from single-environment to multi-environment projects.

```bash
dotsec eject                         # creates dotsec.schema, strips directives from .sec
dotsec eject --output my.schema      # custom output path
```

What it does:

1. Reads the `.sec` file (decrypts if needed)
2. Separates per-key directives (schema) from file-level directives (env)
3. Writes per-key directives + bare keys to `dotsec.schema`
4. Rewrites `.sec` with only file-level directives + key=value pairs

Refuses if the schema file already exists. Delete it first or use `--output` for a different path.

### Multi-environment workflow

```bash
dotsec eject --sec-file dev.sec      # creates dotsec.schema, cleans dev.sec
cp dev.sec staging.sec               # new env — edit values + file-level directives
cp dev.sec prod.sec                  # new env — edit values + file-level directives
dotsec validate --sec-file prod.sec  # validates against shared schema
```

## `dotsec remove-directives`

Strip per-key directives from a `.sec` file. Requires a `dotsec.schema` to exist. Useful for cleaning up `.sec` files that have inline directives after a schema has been created.

```bash
dotsec remove-directives
dotsec remove-directives --sec-file staging.sec
```

## `dotsec push`

Push variables to AWS SSM Parameter Store and/or Secrets Manager based on `@push` directives:

```bash
dotsec push
```

## `dotsec rotate-key`

Generate a new data encryption key (DEK) and re-encrypt all values:

```bash
dotsec rotate-key
```

This decrypts all values with the old DEK, generates a new DEK via KMS, re-encrypts everything, and updates `__DOTSEC_KEY__`. Use this periodically or after a suspected key compromise.

## `dotsec migrate`

Migrate from dotsec v4 format to v5:

```bash
dotsec migrate
```

## `dotsec schema export`

Export the `dotsec.schema` as JSON Schema (draft-07). Useful for integrating with external tools like `env-schema`, VS Code, or CI linters.

```bash
dotsec schema export                          # JSON Schema to stdout
dotsec schema export -o env.schema.json       # write to file
```

All directive types are mapped: `@type` → JSON Schema types, `@format` → JSON Schema formats, `@pattern` → pattern, `@min`/`@max` → minimum/maximum, `@min-length`/`@max-length` → minLength/maxLength, `@optional` → omitted from required, `@deprecated` → deprecated flag.

## `dotsec schema codegen`

Generate typed code from `dotsec.schema`. Currently supports TypeScript.

```bash
dotsec schema codegen                         # TypeScript to stdout
dotsec schema codegen --lang typescript       # explicit (same)
dotsec schema codegen -o src/env.ts           # write to file
```

Generates an `Env` interface with proper types and a `parseEnv()` function that validates environment variables at startup and returns a typed object. Zero runtime dependencies — the generated code is the validator.

```typescript
import { parseEnv } from './env'

const env = parseEnv()  // validates + throws on error
env.PORT                // number
env.NODE_ENV            // "development" | "staging" | "production"
```

## Global options

| Flag | Env var | Description |
|------|---------|-------------|
| `--sec-file <FILE>` | `SEC_FILE` | Path to `.sec` file (default: `.sec`) |
| `--schema <FILE>` | `DOTSEC_SCHEMA` | Path to schema file (default: auto-discover `dotsec.schema`) |
| `--debug` | — | Enable debug logging |
