# Directives

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

## Available directives

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

## Push target syntax

```bash
# Simple
# @push=aws-ssm

# With parameters (values must be quoted)
# @push=aws-ssm(path="/myapp/prod", prefix="/app")

# Multiple targets
# @push=aws-ssm(path="/myapp/prod"), aws-secrets-manager(path="/myapp/prod/db")
```

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
