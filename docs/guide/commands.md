# Commands

## `dotsec set`

Add or update a single variable. On a new project with no `.sec` file, auto-creates `.sec` + keypair.

```bash
dotsec set API_KEY sk-live-xxx --encrypt          # encrypted variable
dotsec set PORT 3000                              # plaintext variable
dotsec set                                        # fully interactive
dotsec set API_KEY sk-live-xxx -y                 # skip prompts, auto-detect directives
dotsec set PORT 3000 --type number                # set @type directive
dotsec set RUNTIME_ONLY_VAR <value> --push aws-ssm              # @push only — pushed, never in local env
dotsec set SHARED_VAR <value> --push aws-ssm --also-env         # @push + @also-env — pushed AND in local env
```

Flags: `--encrypt` / `--plaintext` to control encryption, `--type <TYPE>` for the `@type` directive (`string`, `number`, `boolean`, `enum(...)`), `--push <TARGET>` for the `@push` directive (`aws-ssm`, `aws-secrets-manager`), `--also-env` to pair with `--push` so the value is also available via `dotsec run` / `dotsec export` (otherwise v6 excludes push-only entries from env), `-y/--yes` to skip directive prompts, `--no-gitignore` to skip the first-run auto-add of `*.key` to `.gitignore` (see [Setup](/guide/setup#sec-key-is-auto-gitignored)).

When you go through the interactive prompts (`dotsec set` with no value, or with `--push` and no `-y`), choosing a push target triggers a follow-up "Also inject into local env?" prompt — default no, matching the v6 push-only semantics.

Secret-looking names (containing `KEY`, `SECRET`, `PASSWORD`, `TOKEN`, etc.) use masked input in interactive mode.

### Schema-aware mode

When a `dotsec.schema` file exists:

- **Existing key in schema**: updates the value in `.sec` only — no directive prompts
- **New key**: prompts for directives and writes them to `dotsec.schema` (not inline in `.sec`)
- **No schema**: directives go inline in `.sec`

## `dotsec init`

Interactive setup for an existing project with a specific encryption provider:

```bash
dotsec init                    # prompts for provider (local or aws), config, and defaults
dotsec init --no-gitignore     # skip auto-adding *.key to .gitignore
```

For most projects, `dotsec set` on a new file handles this automatically. Use `init` when you need AWS KMS or want explicit control over the config.

Flags: `--no-gitignore` (same semantics as on `dotsec set` — skip auto-`.gitignore` of the generated keypair file; see [Setup](/guide/setup#sec-key-is-auto-gitignored)).

## `dotsec import`

Migrate a `.env` file into `.sec`:

```bash
dotsec import                  # import from .env (default)
dotsec import .env.production  # import from specific file
dotsec import -y               # auto-accept with heuristic type detection
```

If `.sec` already exists, offers: import new variables only, overwrite all, or cancel. Source `.env` directives pre-populate the prompts as defaults.

The `-y` flag skips per-variable prompts. If `.sec` doesn't exist yet, config (provider, key, region) is taken from the source `.env`'s directives when present, else defaults are used silently — `-y` never falls back to interactive prompts.

## `dotsec export`

Decrypt `.sec` and write to `.env`:

```bash
dotsec export              # decrypt .sec → stdout
dotsec export -o .env      # decrypt .sec → .env file
```

## `dotsec show`

Display decrypted `.sec` contents. Values are masked by default.

```bash
dotsec show                              # raw key=value (masked)
dotsec show --reveal                     # raw key=value (plaintext)
dotsec show --output-format json         # JSON object
dotsec show --output-format csv          # CSV format
dotsec show --output-format text         # formatted text
```

`--output-format` also reads from `DOTSEC_SHOW_OUTPUT_FORMAT`.

## `dotsec run`

Decrypt `.sec` in memory and inject env vars into a child process. Encrypted values are automatically redacted from stdout/stderr.

```bash
dotsec run -- node server.js                  # from .sec (decrypts)
dotsec run --env-file .env -- cargo test      # from plain .env
dotsec run --env-file .env.local -- sh        # custom .env path
```

The `--` separates dotsec options from your command. The child process runs in a pseudo-terminal (PTY), so colors, interactive output, and `isatty()` detection work automatically.

`${VAR}` interpolation is resolved before injection. Single-quoted values are not interpolated (bash convention).

## `dotsec validate`

Check directives and values against type constraints:

```bash
dotsec validate
dotsec validate --schema ./path/to/schema    # explicit schema path
```

Validates: type mismatches, format violations, pattern mismatches, min/max range violations, min-length/max-length, empty values with `@not-empty`, deprecated warnings, and shell environment overrides.

When a `dotsec.schema` file exists:

- Missing keys (in schema but not in `.sec`, unless `@optional`)
- Extra keys (in `.sec` but not in schema)
- Inline per-key directives in `.sec` files are an **error** — move them to the schema or remove them with `dotsec remove-directives`

Errors cause exit code 1. Warnings are displayed but do not affect the exit code.

## `dotsec format`

Reorder entries in a `.sec` file to match the key ordering defined in the schema:

```bash
dotsec format                              # format .sec to match schema order
dotsec format --sec-file staging.sec       # format a specific file
```

Keys defined in the schema are emitted in schema order. Keys not in the schema are appended at the end.

## `dotsec diff`

Compare `.sec` files for structural differences. The `--sec-file` (default `.sec`) is always included; positional args add more files to compare. The most recently modified file is auto-selected as the reference.

```bash
dotsec diff .sec.staging                              # compare default .sec vs .sec.staging
dotsec diff .sec.staging .sec.production              # compare three files (.sec + both)
dotsec diff --values .sec.staging                     # include value differences
```

Reports: missing keys, extra keys, directive mismatches, ordering differences, and optionally value differences.

## `dotsec extract-schema`

Extract per-key directives from a `.sec` file into a `dotsec.schema` file. This is the migration path from a single `.sec` file to a multi-environment setup. Also available as `dotsec eject` (alias).

```bash
dotsec extract-schema                    # creates dotsec.schema, strips directives from .sec
dotsec extract-schema --output my.schema # custom output path
dotsec eject                             # same as `dotsec extract-schema`
```

What it does:

1. Reads the `.sec` file (decrypts if needed)
2. Separates per-key directives (schema) from file-level directives (env config)
3. Writes per-key directives + bare keys to `dotsec.schema`
4. Rewrites `.sec` with only file-level directives + key=value pairs

Refuses if the schema file already exists. Delete it first or use `--output` for a different path.

### Multi-environment workflow

```bash
dotsec extract-schema                    # creates dotsec.schema, cleans .sec
cp .sec .sec.staging                     # new env — edit values + file-level directives
cp .sec .sec.production
dotsec validate --sec-file .sec.staging  # validates against shared schema
```

## `dotsec remove-directives`

Strip inline per-key directives from a `.sec` file. Useful after `extract-schema` or when fixing validation errors caused by leftover inline directives.

```bash
dotsec remove-directives
dotsec remove-directives --sec-file staging.sec
```

## `dotsec header`

Add or update the dotsec header in an existing `.sec` file. Idempotent — safe to run multiple times.

```bash
dotsec header
dotsec header --sec-file .sec.staging
```

The header identifies the file as a dotsec secrets file and includes a link to the docs. New `.sec` files created by `dotsec set` or `dotsec init` include the header automatically.

## `dotsec push`

Push variables to AWS SSM Parameter Store and/or Secrets Manager based on `@push` directives:

```bash
dotsec push                              # push all variables with @push
dotsec push API_KEY DB_URL               # push only specific keys
dotsec push --dry-run                    # show what would be pushed, no API calls
dotsec push -y                           # skip confirmation prompt
```

## `dotsec encrypt`

Re-encrypt the `.sec` file under its current directives and refresh the file's integrity tag. Use this after editing directives (`@encrypt` / `@plaintext` toggles, `@push` target changes, `dotsec.schema` edits) when the next `dotsec run` / `dotsec show` fails with an integrity error.

```bash
dotsec encrypt
```

The command:
1. Reads the file, bypassing the file-level integrity tag (per-value AEAD still authenticates every `ENC[…]`).
2. Reloads `dotsec.schema` so its directives merge into the encrypt pass.
3. Re-runs the standard encrypt pipeline — values with `@encrypt` get encrypted, values with `@plaintext` stay plaintext, and the wrapped DEK is preserved.
4. Writes a fresh MAC into the `@dotsec(...)` directive.

This is the recovery path the integrity-failure message points at: when the file's intent changed but the on-disk integrity tag hadn't been refreshed yet, `dotsec encrypt` brings them back into sync. See [encryption guide → File-level integrity tag](/guide/encryption#file-level-integrity-tag) for the full threat model.

## `dotsec rotate-key`

Generate a new data encryption key (DEK) and re-encrypt all values:

```bash
dotsec rotate-key
```

For local encryption: generates a new DEK wrapped with the same age key. For AWS KMS: requests a new data key from KMS. Either way, all values are re-encrypted and the `@dotsec(...)` directive's `dek=` and `mac=` fields are refreshed.

## `dotsec migrate`

Migrate from dotsec v4 (`dotsec.config.ts` + plaintext `.env`) to v5 `.sec` format:

```bash
dotsec migrate                                       # uses dotsec.config.ts and .env
dotsec migrate .env.production                       # specify env-file
dotsec migrate --config dotsec.config.staging.ts     # specify v4 config
```

Arguments: positional `[env-file]` (default `.env`, also reads `ENV_FILE`) for the plaintext source, `-c, --config <FILE>` (default `dotsec.config.ts`) for the v4 config.

## `dotsec schema export`

Export the `dotsec.schema` as JSON Schema or TypeScript types:

```bash
dotsec schema export                          # JSON Schema to stdout
dotsec schema export -o env.schema.json       # write to file
dotsec schema export --format ts              # TypeScript types to stdout
dotsec schema export --format ts -o src/env.ts  # write to file
```

TypeScript output generates an `Env` interface and a `parseEnv()` function:

```typescript
import { parseEnv } from './env'

const env = parseEnv()  // validates at startup, throws on error
env.PORT                // number
env.NODE_ENV            // "development" | "staging" | "production"
```

Zero runtime dependencies — the generated code is the validator.

JSON Schema output maps all directive types: `@type` → JSON Schema types, `@format` → formats, `@pattern` → pattern, `@min`/`@max` → minimum/maximum, `@optional` → omitted from required, `@deprecated` → deprecated flag.

## No subcommand

Running `dotsec` with no subcommand renders a brand poster: the `.sec` wordmark, quick-start commands for both the local and AWS providers, and the full MIT license text. There is no separate `dotsec license` subcommand — the poster is the license screen.

## Global options

| Flag | Env var | Description |
|------|---------|-------------|
| `-s, --sec-file <FILE>` | `SEC_FILE` | Path to `.sec` file (default: `.sec`) |
| `--schema <FILE>` | `DOTSEC_SCHEMA` | Path to schema file (default: auto-discover `dotsec.schema`) |
| `-d, --debug` | — | Enable debug logging |
| `-h, --help` | — | Print help |
| `-V, --version` | — | Print version |
| — | `DOTSEC_PRIVATE_KEY` | Age private key for local-provider decryption — checked before any `<sec>.key` file |
