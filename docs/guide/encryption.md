# How Encryption Works

## Overview

dotsec uses **per-value envelope encryption**: each secret is encrypted individually with a data encryption key (DEK), so `.sec` files are git-mergeable — changing one secret only affects that line.

Two providers are supported:

- **Local** (default) — age (X25519 + ChaCha20-Poly1305) keypair, no cloud account needed
- **AWS KMS** — IAM-controlled access, CloudTrail audit logs, enterprise teams

## Local encryption (default)

dotsec uses [age](https://age-encryption.org/) for key management. Each `.sec` file has a corresponding keypair.

<!-- TODO: add a "Why age?" section here. Cover: small audited library (Cure53 2021),
multi-recipient support enables painless team key rotation later, standard interchange
format (`age`/`rage` CLI can decrypt the wrapped DEK if dotsec ever broke), no curve or
parameter choices to footgun, maintained Rust crate by the spec author. Contrast vs. raw
libsodium/NaCl sealed boxes (no multi-recipient, no interchange format) and GPG (too much
surface area, web-of-trust we don't need). -->


### How it works

1. On first use, generate an X25519 keypair → store private key in `.sec.key`
2. Generate a random AES-256 DEK
3. Wrap the DEK using age (X25519 + ChaCha20-Poly1305) with the public key
4. Encrypt each secret value locally with AES-256-GCM using the DEK
5. Store the age-wrapped DEK as `__DOTSEC_KEY__` in the `.sec` file

On decryption, load the private key (from `DOTSEC_PRIVATE_KEY` env var or `.sec.key` file), unwrap the DEK, decrypt each `ENC[...]` value locally.

### What the `.sec` file looks like

```bash
# dotsec v6.0.0 — encrypted environment file
# https://github.com/jpwesselink/dotsec-rs

# @dotsec(format=v3, mac=base64-32-bytes..., dek=base64-age-wrapped-dek...)
# @provider=local @default-encrypt

# @encrypt
DATABASE_URL=ENC[base64...]

# @plaintext
NODE_ENV="production"
```

The first non-banner line is the **`@dotsec(...)` directive**: a single file-level directive carrying the format tag, the file-level integrity tag, and the wrapped DEK. It uses the same `@name` syntax as every other directive in `.sec`, so there's no second mini-grammar to learn — but its three params are paren-grouped to signal "this whole blob belongs together, don't edit by hand."

### Key file

The private key is stored in `.sec.key` as a plain age identity string:

```
AGE-SECRET-KEY-1QPZZY...
```

Key discovery order (checked in this order):
1. `DOTSEC_PRIVATE_KEY` environment variable
2. `<sec-file>.key` file alongside the `.sec` file

For CI/CD, use the env var — no file writes needed:

```bash
export DOTSEC_PRIVATE_KEY="AGE-SECRET-KEY-1..."
```

## AWS KMS

For enterprise teams needing IAM-controlled access and CloudTrail audit logs.

### How it works

dotsec uses AWS KMS **envelope encryption**:

1. Request a data key from KMS (`GenerateDataKey` with AES-256)
2. KMS returns both a plaintext DEK and a KMS-wrapped copy
3. Encrypt each secret value locally with AES-256-GCM using the plaintext DEK
4. Store the KMS-wrapped DEK as `__DOTSEC_KEY__` in the `.sec` file
5. Discard the plaintext DEK

On decryption, KMS unwraps the DEK first (`Decrypt`), then each `ENC[...]` value is decrypted locally. The actual secret data never leaves your machine — only the wrapped key touches KMS.

### Setup

See [Setup → AWS KMS](/guide/setup#aws-kms-setup) for configuration steps.

### What the `.sec` file looks like

```bash
# @dotsec(format=v3, mac=base64-32-bytes..., dek=base64-kms-wrapped-dek...)
# @provider=aws @key-id=alias/dotsec @region=us-east-1 @default-encrypt

DATABASE_URL=ENC[base64...]
NODE_ENV="production"
```

## Ciphertext format

Every `ENC[...]` value contains:

```
base64(32-byte-commitment || 12-byte-nonce || ciphertext || 16-byte-auth-tag)
```

- **Commitment** — HMAC-SHA256 of the DEK, verified before decryption to detect wrong-key attempts early
- **Nonce** — random 12 bytes per value (no nonce reuse even if the value is unchanged)
- **Padding** — plaintext is padded to 64-byte blocks with 0–1 random extra blocks to hide length

## File-level integrity tag

In addition to per-value AEAD (which authenticates each `ENC[...]` against its key name), the `@dotsec(...)` directive carries a **file-level integrity tag**: HMAC-SHA256 of the DEK over a canonical serialization of the file.

### What the MAC covers

| Covered | Not covered |
|---|---|
| Every entry's **name** (add / remove / rename detected — encrypted *and* plaintext) | Plaintext **values** (`PORT=3000` → `PORT=4000` edits don't trip the MAC) |
| **Encrypted entries**: all inline directives (`@encrypt`, `@push`, `@type`, `@pattern`, …) | **Plaintext entries**: inline directives (move them into `dotsec.schema` to get coverage — see below) |
| **Encrypted entries**: the `ENC[...]` ciphertext bytes (rollback-resistant) | Comments, whitespace, blank lines |
| Entry **ordering** (file order is part of the canonical — applies to plaintext and encrypted entries alike) | The `mac=` field itself |
| File-level directives (`@provider`, `@key-id`, `@region`, `@default-encrypt`) |  |
| Hash of `dotsec.schema` canonical form |  |

The scope is deliberately split: **structure** (what entries exist, what they're called, what's encrypted and how) is integrity-protected by the MAC. **Plaintext value content** is integrity-protected by the schema — when one exists.

### What this defeats

- **Directive tampering** on encrypted entries: flipping `@encrypt` off, redirecting `@push` to an attacker-owned target, weakening `@type` on an encrypted entry to bypass validation, swapping `@key-id` to an attacker's KMS key.
- **Ciphertext rollback**: substituting `DB_PASSWORD=ENC[old-value]` from a git history (per-value AEAD doesn't catch this because it only binds to the key name; the MAC over ENC bytes does).
- **Entry add / remove / rename / reorder**: an attacker can't inject `EXFIL_URL=https://attacker.example`, drop a sensitive key, or reorder entries to confuse downstream consumers — even for plaintext entries, the *name* is covered.
- **Schema tampering**: editing `dotsec.schema` to drop `@max=65535` or weaken `@type` invalidates every `.sec` file's MAC. The schema hash is canonicalized — adding `@description` or reordering keys is a no-op, only semantic changes flip the hash.

### What this does **not** defeat — and how to compensate

- **Editing a plaintext value in place.** `PORT=3000` → `PORT=4000` passes through. The threat model: an attacker who can write the file can already rewrite a plaintext value to something that influences your app's runtime behavior (a path, a URL, a hostname). **Compensate by putting validation rules in `dotsec.schema`** (`@type=enum(...)`, `@pattern=...`, `@max=...`) — `dotsec validate` runs them on every load and catches tampered values.
- **Editing an inline directive on a *plaintext* entry.** If you write `# @type=enum("prod","staging")\nENV=prod` inline in `.sec`, an attacker can flip the directive to `@type=string` without tripping the MAC. **Compensate by moving plaintext validation directives into `dotsec.schema`** — schema directives ARE bound via `schema_hash`, so semantic schema changes invalidate every file's MAC.
- **An attacker who controls both the `.sec` file and the DEK.** Defense in depth ends at key compromise.

### When the MAC fails

You'll see something like this on `dotsec run`, `dotsec show`, `dotsec validate`, etc.:

```
error: The .sec file has changed in a way dotsec can't verify.

Something an attacker could weaponize — a directive, an ENC[…] value, the
schema, or the set of entries in the file — doesn't match the integrity tag
stored when the file was last written by dotsec.

Two ways this happens:

  1. You (or a teammate) hand-edited the file. Common cases that trip this:
       • adding or removing a variable (encrypted or plaintext);
       • renaming a variable;
       • editing a directive (e.g. `@encrypt`, `@push`, `@type`);
       • editing an ENC[…] payload or the schema file.
     To accept the new state, run:

       dotsec encrypt

     This refreshes the integrity tag against what's currently on disk. (Tip:
     prefer `dotsec set` for routine edits — it re-MACs automatically.)

  2. Someone tampered with the file. Running `dotsec encrypt` now would
     silently bless the tamper. Restore from git or your last known good
     backup and investigate before doing anything else.
```

If you legitimately changed something (added a variable, edited a directive, edited the schema), run `dotsec encrypt` to re-MAC. If you didn't change anything, treat it as tampering and restore from git first.

## Git mergeability

Because each value is encrypted independently, two developers can change different secrets in the same `.sec` file and merge without conflicts:

```diff
  # @encrypt
- API_KEY=ENC[old-value...]
+ API_KEY=ENC[new-value...]

  # @encrypt
  DB_PASSWORD=ENC[unchanged...]
```

Only the lines that were actually modified show up in the diff. The wrapped DEK in the `@dotsec(...)` directive stays the same as long as the key isn't rotated; the `mac=` field updates on every write to reflect the new file state.

## Key rotation

Rotate the DEK without changing any plaintext values:

```bash
dotsec rotate-key
```

This decrypts all values with the old DEK, generates a new DEK (local: new random DEK wrapped with the same age key; KMS: new data key from KMS), and re-encrypts everything. The `dek=` and `mac=` fields in the `@dotsec(...)` directive are both refreshed.

Use this periodically or after a suspected key compromise. For a full key compromise (private key leaked), generate a new keypair first:

```bash
# Local: generate a new keypair, then rotate
dotsec init          # generates new .sec.key
dotsec rotate-key    # re-wraps all values with new key
```
