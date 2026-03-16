# How Encryption Works

## Overview

dotsec uses **per-value envelope encryption**: each secret is encrypted individually with a local data encryption key (DEK), so `.sec` files are git-mergeable.

1. Parse `.sec`, find entries with `@encrypt` (or file-level `@default-encrypt`)
2. Generate a DEK via AWS KMS (`GenerateDataKey` → AES-256)
3. Encrypt each secret value locally with AES-256-GCM → `ENC[base64(nonce || ciphertext || tag)]`
4. Store the KMS-wrapped DEK as `__DOTSEC_KEY__="base64(wrapped-dek)"`

Since each value is encrypted independently, changing one secret only changes that line in the `.sec` file — git merges work naturally.

## Envelope encryption

dotsec uses AWS KMS **envelope encryption**:

1. Request a data key from KMS (`GenerateDataKey` with AES-256)
2. KMS returns both a plaintext DEK and a KMS-wrapped copy
3. Encrypt each secret value locally with AES-256-GCM using the plaintext DEK (random 12-byte nonce per value)
4. Store the wrapped DEK as `__DOTSEC_KEY__` in the `.sec` file
5. Discard the plaintext DEK

On decryption, KMS unwraps the DEK first (`Decrypt`), then each `ENC[...]` value is decrypted locally with AES-256-GCM. The actual secret data never leaves your machine — only the wrapped key touches KMS.

## What gets committed

```bash
# @provider=aws @key-id=alias/dotsec @region=us-east-1 @default-encrypt

# @encrypt
# @type=string
DATABASE_URL=ENC[base64...]   # ← encrypted with DEK (AES-256-GCM)

# @plaintext
# @type=string
NODE_ENV="production"         # ← real value, visible in git

# do not edit the line below, it is managed by dotsec
__DOTSEC_KEY__="base64-encoded-kms-wrapped-dek..."
```

The `__DOTSEC_KEY__` line contains the KMS-wrapped data encryption key. Each `ENC[...]` value contains `base64(12-byte-nonce || ciphertext || 16-byte-auth-tag)`. Without KMS access, the encrypted values are opaque.

## Key rotation

Rotate the DEK without changing any plaintext values:

```bash
dotsec rotate-key
```

This generates a new DEK via KMS, decrypts all values with the old key, and re-encrypts them with the new one. The `__DOTSEC_KEY__` line is updated with the new wrapped DEK.

## Git mergeability

Because each value is encrypted independently, two developers can change different secrets in the same `.sec` file and merge without conflicts:

```diff
  # @encrypt
- API_KEY=ENC[old-value...]
+ API_KEY=ENC[new-value...]

  # @encrypt
  DB_PASSWORD=ENC[unchanged...]
```

Only the lines that were actually modified show up in the diff. The `__DOTSEC_KEY__` stays the same as long as the key isn't rotated.
