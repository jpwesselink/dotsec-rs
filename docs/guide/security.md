# Security Model

What dotsec protects, what it assumes, and what it explicitly does not defend against. For the mechanics (ciphertext format, MAC scope, key wrapping) see [How Encryption Works](/guide/encryption).

## The core claim

A `.sec` file is safe to publish. The design assumes the file is world-readable — committed to a public repo, attached to a PR, cached by a CI runner. Everything sensitive in it is AES-256-GCM encrypted with a 256-bit DEK, and the DEK is wrapped by your age keypair or AWS KMS.

What's secret is the **key**, never the file:

| Provider | The secret | Where it lives |
|---|---|---|
| Local (age) | `.sec.key` / `DOTSEC_PRIVATE_KEY` | Your machine, your team's password manager, CI secrets |
| AWS KMS | IAM permission to call `kms:Decrypt` | AWS — the private key material never leaves KMS |

## What an attacker with the `.sec` file can do

Nothing useful, by design — but precisely:

| Attacker capability | Outcome |
|---|---|
| Read encrypted values | Sees `ENC[...]` blobs. Padding hides plaintext length to a 64-byte block. |
| Read plaintext values | Sees them — that's what `@plaintext` means. Don't mark secrets plaintext. |
| Swap a ciphertext between keys (`DB_PASSWORD` → `API_KEY`) | Rejected — per-value AEAD binds each ciphertext to its key name. |
| Roll back one value to an older ciphertext from git history | Rejected — the file MAC covers the `ENC[...]` bytes. |
| Add, remove, rename, or reorder entries | Rejected — entry names and order are MAC-covered, plaintext included. |
| Flip `@encrypt` off, redirect `@push`, weaken `@type` on an encrypted entry | Rejected — directives on encrypted entries are MAC-covered. |
| Weaken `dotsec.schema` (drop `@max`, loosen `@pattern`) | Rejected — a canonical hash of the schema is bound into the MAC. |
| Edit a plaintext **value** in place (`PORT=3000` → `PORT=4000`) | **Passes.** Deliberate — see below. |

The last row is the documented gap: plaintext values are not MAC-covered, so hand-editing them stays friction-free. Compensate by putting validation rules (`@type`, `@pattern`, `@min`/`@max`, `enum(...)`) in `dotsec.schema` — the schema *is* integrity-bound, and `dotsec validate` enforces it on every load.

## Assumptions

- **The directory containing `.sec` is not writable by a hostile local user.** dotsec's atomic writes (`O_EXCL` temp file + rename, 0600 permissions) prevent symlink-following and clobbering, but a local attacker with write access to the directory can at worst deny service — that boundary is the OS's, not dotsec's.
- **Key compromise ends the story.** An attacker holding both the file and the private key (or `kms:Decrypt` rights) reads everything. There is no defense-in-depth below the key.
- **`panic = "abort"` in release builds** means destructors don't run on panic, so best-effort memory zeroing (`Zeroizing` on DEKs, plaintext buffers, key files) covers normal and error paths but not panic paths.
- **`dotsec migrate` executes the v4 config.** A `dotsec.config.{ts,js}` is code; migrating runs it. Only migrate configs you trust — see [the migrate command](/guide/commands#dotsec-migrate).

## Engineering posture

- **Fuzzing.** The parser surface that consumes untrusted `.sec` content (grammar, `@dotsec(...)` header, schema files, parse→render round-trip) is covered by four `cargo-fuzz` targets with curated seed corpora — see `fuzz/` in the repo.
- **Dependency audit.** CI runs `cargo audit` on every push; ignores live in `.cargo/audit.toml`, each with a written rationale.
- **Memory hygiene.** DEKs, decrypted values, and key-file contents are wrapped in `Zeroizing` at the moment secret material enters them, so every exit path (including errors) wipes them.
- **Constant-time comparisons** for the file MAC and the key commitment (via `subtle`).
- **No secrets over FFI.** The `@dotsec/core` Node bindings expose parsing, validation, and formatting only — no decrypt, no key material crosses the boundary.

## Wire format history

The on-disk envelope is versioned by the `format=` field in the `@dotsec(...)` directive, independent of the package version.

| Format | Era | Mechanism |
|---|---|---|
| **v1** | JS-era `dotsec` npm package | Per-value KMS `Encrypt` calls, chunked; stored as `KEY="{hash, parts: [...]}"`. No envelope, no AAD, no padding. |
| **v2** | First Rust releases | Per-value AES-256-GCM envelope: a single wrapped DEK (carried as a `__DOTSEC_KEY__` entry), AAD binding to the key name, key commitment, length padding. |
| **v3** | Current | v2 plus a file-level integrity tag (HMAC-SHA256 over a canonical serialization), schema-hash binding, and the header moved into the `@dotsec(format=v3, mac=..., dek=...)` directive. |

Readers reject unknown `format=` tags rather than guessing. The format version only bumps when the envelope changes incompatibly — package majors come and go without touching it.

## Reporting

Found something? Open a [GitHub security advisory](https://github.com/jpwesselink/dotsec-rs/security/advisories/new) — please don't file public issues for suspected vulnerabilities.
