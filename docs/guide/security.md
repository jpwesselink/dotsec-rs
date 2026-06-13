# Security Model

What dotsec protects, what it assumes, and what it explicitly does not defend against. For the mechanics (ciphertext format, MAC scope, key wrapping) see [How Encryption Works](/guide/encryption).

## The core claim

A `.sec` file is safe to publish. The design assumes the file is world-readable — committed to a public repo, attached to a PR, cached by a CI runner. Everything sensitive in it is AES-256-GCM encrypted with a 256-bit data encryption key (DEK), and the DEK is wrapped by your age keypair or AWS KMS.

What's secret is the **key**, never the file:

| Provider | The secret | Where it lives |
|---|---|---|
| Local (age) | `.sec.key` / `DOTSEC_PRIVATE_KEY` | Your machine, your team's password manager, CI secrets |
| AWS KMS | IAM permission to call `kms:Decrypt` | AWS — the private key material never leaves the HSM |

The KMS path is the strongest version of this. With KMS, dotsec is a thin client and **the trust root is the HSM that backs your existing AWS account** — the same one your compliance team has already approved for every other workload. dotsec is not a vendor you trust; AWS is, and you trust them already.

## How the cryptography is built

The properties below are visible in the source — they're not marketing claims.

| Property | How |
|---|---|
| Per-value confidentiality | AES-256-GCM, fresh 96-bit nonce per value, separately keyed under the DEK |
| Per-value tamper detection | AEAD authentication tag covers ciphertext; AAD binds each ciphertext to its key name so values can't be swapped between keys |
| File-level integrity | HMAC-SHA256 over a canonical serialization covering entry names, order, ENC bytes, file-level directives, directives on encrypted entries, and a hash of `dotsec.schema` |
| Rollback resistance | The file MAC covers ENC ciphertext bytes, so substituting an older blob from git history breaks verification |
| Wrong-key detection | 32-byte key commitment over the DEK, checked before AEAD decrypt |
| Plaintext-length hiding | Plaintext padded to a 64-byte multiple plus a random extra block |
| Confidentiality at rest in process memory | DEKs, decrypted plaintext, key-file contents wrapped in `Zeroizing` at the moment secret material enters them — every error path wipes |
| Timing-safe integrity comparison | MAC and key-commitment checks via `subtle` (constant-time) |
| Parser robustness on untrusted input | Cargo-fuzz harness with four targets covering `.sec` parsing, schema parsing, header parsing, and parse → render idempotency |

For the full wire-format details and the explicit list of what the MAC does *not* cover (and why), read on.

## What an attacker with the `.sec` file can do

Nothing useful, by design — but precisely:

| Attacker capability | Outcome |
|---|---|
| Read encrypted values | Sees `ENC[...]` blobs. Padding rounds plaintext up to a 64-byte multiple, plus a randomly added extra block — observed ciphertext length doesn't pin down the plaintext length. |
| Read plaintext values | Sees them — that's what `@plaintext` means. Don't mark secrets plaintext. |
| Swap a ciphertext between keys (`DB_PASSWORD` → `API_KEY`) | Rejected — per-value AEAD binds each ciphertext to its key name. |
| Roll back one value to an older ciphertext from git history | Rejected — the file MAC covers the `ENC[...]` bytes. |
| Add, remove, rename, or reorder entries | Rejected — entry names and order are MAC-covered, plaintext included. |
| Flip `@encrypt` off, redirect `@push`, weaken `@type` on an encrypted entry | Rejected — directives on encrypted entries are MAC-covered. |
| Weaken `dotsec.schema` (drop `@max`, loosen `@pattern`) | Rejected — a canonical hash of the schema is bound into the MAC. |
| Edit a plaintext **value** in place (`PORT=3000` → `PORT=4000`) | **Passes.** Deliberate — see below. |

The last row is the documented gap: plaintext values are not MAC-covered, so hand-editing them stays friction-free. Compensate by putting validation rules (`@type`, `@pattern`, `@min`/`@max`, `enum(...)`) in `dotsec.schema` — the schema *is* integrity-bound, and `dotsec validate` enforces it on every load.

## On-disk surface area

dotsec is designed so the only sensitive artifact on a developer's machine is the private key — and even that can move off-disk:

| Setup | What sits on disk | Defense surface |
|---|---|---|
| dotsec, local provider | `.sec` (encrypted, committed) + `.sec.key` (gitignored) | Same as any private-key-on-disk model. Key file inherits the OS's filesystem permissions. |
| dotsec, local provider with `DOTSEC_PRIVATE_KEY` injected | `.sec` only | No key material on disk — comes from an env var that any wrapping tool (password manager CLI, `direnv`, `gpg --decrypt`) can fill in at spawn time |
| dotsec, AWS KMS provider | `.sec` only | **No key material on disk at all.** The wrapped DEK is in `.sec` but is opaque to anyone without `kms:Decrypt`. The KEK lives in the AWS HSM. |

The KMS row matters for the supply-chain attack class — when a compromised dependency's postinstall script runs as your user and grep-walks the filesystem for `.env`, `.sec.key`, AWS credentials, etc., there's simply nothing to find. The wrapped DEK in `.sec` is useless without an IAM-authenticated, CloudTrail-logged call to KMS, which the malicious script cannot make undetected.

:::tip Harden the local provider further
`DOTSEC_PRIVATE_KEY` is checked before any key file ([discovery order](/guide/encryption#key-file)), so any tool that can inject an env var into a child process can take over key delivery — letting you delete `.sec.key` from disk. Examples worth exploring: the [1Password CLI](https://developer.1password.com/docs/cli/) (`op run` resolves `op://` secret references), [direnv](https://direnv.net/) bound to a keychain command, or a shell function that reads from `gpg --decrypt`.
:::

## Assumptions

- **dotsec can't stop same-user code from clobbering `.sec.key`.** Use the KMS provider if that's in your threat model — no key file.
- **Key compromise ends the story.** An attacker holding both the file and the private key (or `kms:Decrypt` rights) reads everything. There is no defense-in-depth below the key.
- **`panic = "abort"` skips destructor-based memory wipe.** Two layers defend against the resulting coredump exposure: the fuzz harness keeps the input-driven panic surface closed, and `dotsec` calls `setrlimit(RLIMIT_CORE, 0)` at startup so a panic can't drop a dump containing in-flight secrets in the first place.
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
