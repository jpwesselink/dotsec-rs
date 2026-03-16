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
dotsec validate                 # validate .env
dotsec validate --using sec     # decrypt and validate .sec
```

Validates: unknown directives, type mismatches (number, boolean, enum membership), missing directive values, and shell environment overrides.

## `dotsec diff`

Compare `.sec` files for structural differences. Auto-selects the most recently modified file as the reference:

```bash
dotsec diff .sec.staging                  # compare default .sec vs .sec.staging
dotsec diff .sec.staging .sec.production  # compare all three (default .sec included)
dotsec diff --values .sec.staging         # include value differences
```

Reports: missing keys, extra keys, directive mismatches, ordering differences, and optionally value differences.

## `dotsec rotate-key`

Generate a new data encryption key (DEK) and re-encrypt all values:

```bash
dotsec rotate-key
```

This decrypts all values with the old DEK, generates a new DEK via KMS, re-encrypts everything, and updates `__DOTSEC_KEY__`. Use this periodically or after a suspected key compromise.
