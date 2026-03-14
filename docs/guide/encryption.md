# How Encryption Works

## Overview

1. Parse `.sec`, find entries with `@encrypt` (or file-level `@default-encrypt`)
2. Generate a random 64-char hex ID for each encrypted value
3. Replace encrypted values with their IDs in the `.sec` output
4. Build a `{id: real_value}` map, serialize to JSON
5. Encrypt the JSON blob using AWS KMS envelope encryption (AES-256-GCM + KMS data key wrapping)
6. Append as `__DOTSEC__="<base64>"` to the `.sec` file

Re-encrypting reuses IDs for unchanged values — only modified secrets get new IDs, keeping git diffs minimal.

## Envelope encryption

dotsec uses AWS KMS **envelope encryption**:

1. Request a data key from KMS (`GenerateDataKey`)
2. KMS returns both a plaintext key and an encrypted copy of that key
3. Encrypt the secrets JSON with AES-256-GCM using the plaintext key
4. Store the encrypted data key alongside the ciphertext
5. Discard the plaintext key

On decryption, KMS decrypts the data key first, then AES-256-GCM decrypts the secrets. This means the actual secret data never leaves your machine unencrypted — only the data key touches KMS.

## What gets committed

```bash
# @provider=aws @key-id=alias/dotsec @region=us-east-1 @default-encrypt

# @encrypt
DATABASE_URL="a1b2c3d4e5f6..."   # ← random hex ID, not the real value

# @plaintext
NODE_ENV="production"             # ← real value, visible in git

__DOTSEC__="base64-encoded-encrypted-blob..."
```

The `__DOTSEC__` line contains the encrypted mapping from hex IDs to real values. Without KMS access, the encrypted values are opaque.
