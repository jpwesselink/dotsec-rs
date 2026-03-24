# QA Plan — PR #11 Manual Testing

Everything below assumes you have AWS credentials configured and a KMS key available.

## Setup

```bash
# Start fresh
mkdir /tmp/dotsec-qa && cd /tmp/dotsec-qa
export PATH="/path/to/dotsec-rs/target/debug:$PATH"
cargo build --workspace   # from the repo
```

---

## 1. Init + Basic Flow (5 min)

```bash
# Create a new .sec file
dotsec init
# → Pick aws, enter your KMS key alias, pick a region, choose default-encrypt
# → Should create .sec with @provider, @key-id, @region, @default-encrypt

cat .sec
# ✓ File has directives at top, no key=value pairs yet
```

## 2. Set Command — Inline Flow (5 min)

```bash
# Add variables (no schema exists, so directives go inline)
dotsec set DATABASE_URL postgres://localhost:5432/mydb --encrypt --type string
dotsec set PORT 3000 --type number
dotsec set NODE_ENV production --plaintext

cat .sec
# ✓ DATABASE_URL is ENC[...] (encrypted)
# ✓ PORT=3000 with @type=number inline
# ✓ NODE_ENV=production with @plaintext inline
# ✓ __DOTSEC_KEY__ at the bottom
```

> **Note:** `set` supports `--encrypt`, `--plaintext`, `--type`, and `--push` flags.
> There is no `--format` flag — format directives are added via interactive prompts or by editing the file/schema directly.

## 3. Show Command — Masking (2 min)

```bash
dotsec show
# ✓ Values are MASKED by default (e.g., "post****", "3000", "prod****")

dotsec show --reveal
# ✓ Values shown in plaintext

dotsec show --output-format json
# ✓ JSON object format: {"DATABASE_URL":"****","PORT":"****",...}

dotsec show --output-format json --reveal
# ✓ JSON with real values

dotsec show --output-format csv --reveal
# ✓ CSV with comma delimiters (NOT tabs)
```

## 4. Validate — Inline (2 min)

```bash
dotsec validate
# ✓ Should pass (all values match their types)

# Force a bad value by editing .sec directly
sed -i '' 's/PORT=3000/PORT=notanumber/' .sec
dotsec validate
# ✓ Should report: PORT expected number, got "notanumber"
# Fix it back
sed -i '' 's/PORT=notanumber/PORT=3000/' .sec
```

> **Note:** Without a schema, `set` does not re-validate existing inline directives when
> updating a value. Validation happens via `dotsec validate`. With a schema (after eject),
> `set` DOES validate against schema constraints before writing.

## 5. Eject — Move to Schema Flow (3 min)

```bash
dotsec eject
# ✓ Creates dotsec.schema with @type, @format, @encrypt, @plaintext directives
# ✓ .sec is rewritten WITHOUT per-key directives (just key=value + file-level config)

cat dotsec.schema
# ✓ Has bare keys with directives above them
# ✓ Has @default-encrypt at top

cat .sec
# ✓ No @type, @format, @encrypt, @plaintext on individual keys
# ✓ Still has @provider, @key-id, @region
# ✓ Still has __DOTSEC_KEY__
```

## 6. Validate — Schema Flow (2 min)

```bash
dotsec validate
# ✓ Should still pass — same constraints, now from schema

# Edit schema to make PORT stricter
# Add @min=0 @max=65535 to PORT in dotsec.schema
dotsec validate
# ✓ Still passes (3000 is in range)

# Break it
sed -i '' 's/PORT=3000/PORT=99999/' .sec
dotsec validate
# ✓ Reports: PORT value 99999 is greater than maximum 65535
sed -i '' 's/PORT=99999/PORT=3000/' .sec
```

## 7. Set — Schema-Aware (3 min)

```bash
# Prerequisite: step 6 added @min=0 @max=65535 to PORT in dotsec.schema

# Set a new key (should go to schema)
dotsec set REDIS_URL redis://localhost:6379 --type string
# ✓ dotsec.schema now has REDIS_URL with @type=string
# ✓ .sec has REDIS_URL=... but NO inline directives

# Set value that violates schema
dotsec set PORT 999999
# ✓ REJECTED — value violates schema constraints (max=65535)

# Update existing key with valid value
dotsec set PORT 8080
# ✓ Accepted, .sec updated
```

## 8. Format — Schema Ordering (2 min)

```bash
# Reorder schema: put PORT first
# Edit dotsec.schema manually, move PORT block above DATABASE_URL

dotsec format
# ✓ .sec keys reordered to match schema
# ✓ PORT now appears before DATABASE_URL in .sec

dotsec validate
# ✓ Still passes after reformatting
```

## 9. Multi-Environment (5 min)

```bash
# Create staging env (shares the same DEK — that's fine for same KMS key)
cp .sec staging.sec

# Edit staging.sec — change values
dotsec set PORT 8081 --sec-file staging.sec
dotsec set NODE_ENV staging --sec-file staging.sec

# Validate staging against shared schema
dotsec validate --sec-file staging.sec
# ✓ Passes — same schema, different values

# Diff
dotsec diff staging.sec
# ✓ Shows: value differences on PORT, NODE_ENV
# ✓ No structural differences (same keys)

dotsec diff --values staging.sec
# ✓ Shows actual value differences
```

## 10. Export — File Permissions (2 min)

```bash
dotsec export -o test.env
ls -la test.env
# ✓ Permissions are 600 (owner read/write only) on macOS/Linux

cat test.env
# ✓ Plaintext key=value pairs, decrypted

rm test.env
```

## 11. Push — Partial Failure (3 min)

```bash
# Add push directive to schema
# Edit dotsec.schema: add @push=aws-ssm to DATABASE_URL

dotsec push
# ✓ Pushes to SSM Parameter Store
# ✓ If any push fails, exit code is non-zero (not silent success)

# Verify in AWS Console or:
aws ssm get-parameter --name DATABASE_URL --with-decryption
```

## 12. Run — Secret Redaction (3 min)

```bash
# Redaction works in PTY mode (direct output, no piping)
dotsec run -- sh -c 'echo $DATABASE_URL'
# ✓ Value is REDACTED in output (replaced with ****)

dotsec run -- sh -c 'echo $PORT'
# ✓ PORT value shown (plaintext values are not redacted)

# Verify env vars are actually injected
dotsec run -- sh -c 'env | grep DATABASE_URL'
# ✓ DATABASE_URL appears (but piped through grep, so PTY redaction may not apply)
# The important thing: the var IS in the child's environment
```

## 13. Import (3 min)

```bash
# Create a .env to import
cat > /tmp/import-test.env << 'EOF'
NEW_KEY=hello
ANOTHER_SECRET=supersecret
EOF

dotsec import /tmp/import-test.env
# ✓ Prompts for each variable (type, encrypt, push)
# ✓ New directives go to dotsec.schema (not inline)
# ✓ Values go to .sec

dotsec validate
# ✓ Passes with new keys
```

## 14. Rotate Key (2 min)

```bash
dotsec rotate-key
# ✓ All ENC[...] values re-encrypted
# ✓ __DOTSEC_KEY__ updated
# ✓ Decrypted values unchanged

dotsec show --reveal
# ✓ Same values as before rotation
```

## 15. Schema Export + Codegen (2 min)

```bash
dotsec schema export
# ✓ JSON Schema output to stdout

dotsec schema export -o env.schema.json
cat env.schema.json
# ✓ Valid JSON Schema with types, constraints, required fields

dotsec schema codegen
# ✓ TypeScript interface + parseEnv() function to stdout

dotsec schema codegen -o env.ts
cat env.ts
# ✓ Proper TypeScript types matching schema
```

## 16. Edge Cases (5 min)

```bash
# Missing schema file
dotsec validate --schema /nonexistent/path
# ✓ Error: "schema file not found: /nonexistent/path"

# DOTSEC_SCHEMA env var with missing file
DOTSEC_SCHEMA=/nonexistent dotsec validate
# ✓ Error: DOTSEC_SCHEMA is set but file does not exist

# Eject when schema already exists
dotsec eject
# ✓ Error: "dotsec.schema already exists"

# Remove directives
dotsec remove-directives
# ✓ Strips any remaining inline directives from .sec (should be none after eject)
```

## 17. Migrate v4 → v5 (5 min)

```bash
cd /tmp/dotsec-qa

# Create a fictional v4 setup
cat > dotsec.config.ts << 'TSEOF'
export default {
  defaults: {
    encryptionEngine: "aws",
    plugins: {
      aws: {
        kms: {
          keyAlias: "alias/dotsec",
        },
        ssm: {
          changeCase: "camelCase",
          pathPrefix: "/myapp/prod",
        },
        secretsManager: {
          changeCase: "camelCase",
          pathPrefix: "/myapp/prod",
        },
      },
    },
  },
  redaction: {
    show: ["NODE_ENV", "PORT", "LOG_LEVEL"],
  },
  push: {
    DATABASE_URL: { aws: { ssm: true, secretsManager: true } },
    API_KEY: { aws: { ssm: true } },
  },
}
TSEOF

cat > v4.env << 'ENVEOF'
# Database
DATABASE_URL=postgres://user:pass@db.example.com:5432/myapp

# API
API_KEY=sk-live-1234567890abcdef

# App config
NODE_ENV=production
PORT=3000
LOG_LEVEL=info
ENVEOF

# Run migration (requires npx/tsx available for config parsing)
dotsec migrate --config dotsec.config.ts v4.env
# ✓ Prompts for confirmation
# ✓ Creates .sec with:
#   - @provider=aws @key-id=alias/dotsec @default-encrypt at top
#   - DATABASE_URL encrypted (not in redaction.show)
#   - API_KEY encrypted (looks_like_secret overrides redaction.show)
#   - NODE_ENV plaintext (in redaction.show, doesn't look like secret)
#   - PORT plaintext (in redaction.show)
#   - LOG_LEVEL plaintext (in redaction.show)
#   - @push directives from push config
#   - __DOTSEC_KEY__ at the bottom

dotsec show --reveal
# ✓ All values match the original .env

dotsec validate
# ✓ Passes
```

## 18. Import with Auto-Accept (2 min)

```bash
cat > /tmp/auto-import.env << 'EOF'
AUTO_PORT=8080
AUTO_NAME=myservice
AUTO_SECRET_KEY=sk-abcdef123456
EOF

dotsec import -y /tmp/auto-import.env
# ✓ No per-variable prompts (auto-detects types)
# ✓ AUTO_PORT detected as number
# ✓ AUTO_SECRET_KEY detected as secret → encrypted
# ✓ AUTO_NAME detected as string
# ✓ If schema exists, directives go to schema
```

## 19. Run with Plain .env (2 min)

```bash
cat > /tmp/plain.env << 'EOF'
PLAIN_VAR=hello
PLAIN_PORT=9090
EOF

dotsec run --using env --env-file /tmp/plain.env -- sh -c 'echo $PLAIN_VAR $PLAIN_PORT'
# ✓ No AWS credentials needed
# ✓ Values injected from plain .env
# ✓ Output: "hello 9090"
```

## 20. Diff with Three Files (2 min)

```bash
# Assumes .sec, staging.sec exist from step 9
cp .sec prod.sec
dotsec set PORT 443 --sec-file prod.sec

dotsec diff staging.sec prod.sec
# ✓ Compares default .sec vs staging.sec vs prod.sec
# ✓ Reports differences across all three
```

## 21. Push to Secrets Manager (2 min)

```bash
# Edit dotsec.schema: add @push=aws-secrets-manager to API_KEY (or any key)
# Or add @push=aws-secrets-manager(path="/myapp/prod/api-key")

dotsec push
# ✓ Pushes to Secrets Manager (not just SSM)
# Verify:
aws secretsmanager get-secret-value --secret-id /myapp/prod/api-key
```

## 22. Pattern Regex Validation (2 min)

```bash
# Edit dotsec.schema: add @pattern="^https?://" to a URL key

dotsec validate
# ✓ Passes if value starts with http:// or https://

# Break it
sed -i '' 's|DATABASE_URL="postgres://|DATABASE_URL="ftp://|' .sec
dotsec validate
# ✓ Error: value does not match pattern
# Fix it back
sed -i '' 's|DATABASE_URL="ftp://|DATABASE_URL="postgres://|' .sec
```

> **Note:** Pattern is on DATABASE_URL which is encrypted. You'd need to decrypt,
> edit, re-encrypt, or use `dotsec set` to change the value.
> Alternatively, test on a plaintext key.

## 23. Deprecated + Optional Keys (2 min)

```bash
# Edit dotsec.schema:
# Add @deprecated="Use NEW_API_KEY instead" to API_KEY
# Add @optional to a new key SENTRY_DSN

dotsec validate
# ✓ Warning: API_KEY is deprecated: "Use NEW_API_KEY instead"
# ✓ No error for missing SENTRY_DSN (it's @optional)
# ✓ Exit code 0 (warnings don't fail)
```

## 24. Unicode Values Through Full Flow (3 min)

```bash
dotsec set GREETING "こんにちは世界" --plaintext
dotsec show
# ✓ Masked: "こんに****"

dotsec show --reveal
# ✓ Full: "こんにちは世界"

dotsec validate
# ✓ Passes

dotsec run -- sh -c 'echo $GREETING'
# ✓ Outputs: こんにちは世界
```

---

## Summary Checklist

| # | Area | Automated tests | Pass? |
|---|---|---|---|
| 1 | Init creates valid .sec | — (interactive CLI) | |
| 2 | Set with inline directives works | `dotsec/src/cli/commands/set.rs` (helpers) | |
| 3 | Show masks by default, --reveal shows values | `dotsec/src/lib.rs` (mask_all_values) | |
| 4 | Validate catches type violations (inline) | `dotenv/src/types.rs` (Entry::validate, 30+ tests) | |
| 5 | Eject splits .sec into .sec + schema | `dotsec/src/cli/helpers.rs` (extract_schema_from_lines) | |
| 6 | Validate works with external schema | `dotenv/src/lib.rs` (validate_entries_against_schema, 19 tests) | |
| 7 | Set respects schema, rejects invalid values | `dotsec/src/cli/commands/set.rs` + `dotenv/src/types.rs` (validate_value_against_constraints) | |
| 8 | Format reorders by schema | `dotenv/src/lib.rs` (format_lines_by_schema, 7 tests) | |
| 9 | Multi-env with shared schema | `dotenv/src/lib.rs` (same validation, no multi-file test) | |
| 10 | Export creates 0600 file | `dotsec/src/cli/commands/export.rs` | |
| 11 | Push fails loudly on errors | — (needs AWS) | |
| 12 | Run redacts secrets in output | `dotsec-core/src/lib.rs` (redact, collect_and_redact_integration) | |
| 13 | Import adds to schema (not inline) | `dotsec/src/cli/helpers.rs` (extract_schema_from_lines) | |
| 14 | Key rotation preserves values | — (needs AWS) | |
| 15 | Schema export + codegen produce valid output | `dotenv/src/lib.rs` (schema_to_json_schema, schema_to_typescript) | |
| 16 | Edge cases error properly | `dotenv/src/lib.rs` (discover_schema) + `dotenv/src/types.rs` (regex limit, unparseable directives) | |
| 17 | Migrate v4 → v5 produces correct .sec | `dotsec/src/cli/commands/migrate.rs` (config parsing, push directives, line building, camelCase) | |
| 18 | Import -y auto-detects types | `dotsec/src/cli/commands/import.rs` (auto_directives) | |
| 19 | Run with plain .env (no AWS) | `dotsec-core/src/lib.rs` (resolve_env_vars, interpolation) | |
| 20 | Diff with three files | `dotenv/src/lib.rs` (diff_entries) | |
| 21 | Push to Secrets Manager | — (needs AWS) | |
| 22 | Pattern regex validation | `dotenv/src/types.rs` (pattern tests + size limit) | |
| 23 | Deprecated + optional key handling | `dotenv/src/lib.rs` (schema_validation_deprecated, schema_optional) | |
| 24 | Unicode values through full flow | `dotsec/src/lib.rs` (mask emoji) + `dotsec/src/cli/helpers.rs` (truncate_value) | |
