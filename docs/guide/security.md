# Security Model

What dotsec protects, what it assumes, and what it explicitly does not defend against. For the mechanics (ciphertext format, MAC scope, key wrapping) see [How Encryption Works](/guide/encryption).

## What dotsec solves — and what it doesn't

> **dotsec reduces exposure of secrets *at rest* — on disk, in repos, in CI caches — especially against the dragnet `postinstall` / filesystem-scrape supply-chain attack class.**
>
> **dotsec does not eliminate secret exfiltration by code running in the same process or the same CI job after dotsec has decrypted.** A malicious dependency running in your application after `dotsec run` has injected env vars can still read those env vars. A compromised CI runner that holds `kms:Decrypt` can still call it.

That's the honest one-paragraph framing. It's a real reduction in attack surface — `.env` files are the single most-harvested artifact in the 2025 npm worm wave, and a `.sec` file is worthless ciphertext to a dragnet. But "no `.env` files" is not the same as "no secret leakage." Anything that claims the second needs a runtime sandbox; dotsec doesn't.

For production-grade use, treat dotsec as **one layer of a layered posture**:

- Prefer **KMS** over the local provider.
- **Least-privileged IAM** on `kms:Decrypt`, scoped to specific roles via the `dotsec:format=v3` encryption context.
- **GitHub Environment protection** on workflows that decrypt — manual approval gate before prod secrets unlock.
- **OIDC federation** instead of long-lived AWS access keys in CI.
- **Separate prod / staging / dev KMS keys** so a dev role can't reach prod material even if it tries.
- **Never run `kms:Decrypt` in jobs that execute untrusted code** (e.g. PRs from forks, dependency installs that haven't been reviewed).

See [CI/CD → security posture](/guide/ci#cicd-security-posture) for a concrete checklist.

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

The last row is the documented gap: plaintext values are not MAC-covered, so hand-editing them stays friction-free. **But "not a secret" is not the same as "safe to leave mutable."** A spectrum to think about:

| Value | Risk if an attacker can mutate it | Recommended |
|---|---|---|
| `PORT=3000` | Process binds to a different local port | Leave plaintext |
| `LOG_LEVEL=info` | Verbosity changes | Leave plaintext |
| `NODE_ENV=production` | App takes a different code path | Schema with `@type=enum(...)` |
| `API_BASE_URL=https://api.acme.com` | **Redirect requests to attacker-controlled endpoint** | Schema with `@pattern` pinning the host, *or* mark `@encrypt` |
| `AUTH_ISSUER=https://login.acme.com` | **OIDC trust redirected to attacker IdP** | `@encrypt` |
| `JWKS_URL`, OAuth `callback_url`, payment endpoint | **Direct security boundary** | `@encrypt` |
| `ALLOWED_ORIGINS=*.acme.com` | **CORS expansion** | Schema `@pattern`, *or* `@encrypt` |
| `FEATURE_FLAG_AUTH_BYPASS=false` | **Disables auth entirely** | `@encrypt` (and reconsider the flag) |

Rule of thumb: if mutating the value alone would shift a **security boundary**, mark it `@encrypt` even if the value itself isn't a credential. Confidentiality isn't the only reason to encrypt — integrity is.

For everything else, put validation rules (`@type`, `@pattern`, `@min`/`@max`, `enum(...)`) in `dotsec.schema`. The schema *is* integrity-bound, and `dotsec validate` runs on every load — a tampered plaintext value that breaks the schema is rejected before your app sees it.

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

## Runtime exposure dotsec does NOT solve

Once `dotsec run` has decrypted, plaintext secrets exist in process memory and in the child process's env vars. From that point on, dotsec is out of the loop. Things that can still leak secrets at runtime:

- **Application logs** — `console.log(process.env)`, `logger.debug({ env })`, request middleware that dumps headers
- **Crash reports** — Sentry, Bugsnag, Rollbar will happily ship `process.env` as breadcrumb context unless you scrub it
- **Telemetry / APM agents** — many auto-instrument env vars
- **Frontend bundles** — webpack / vite / esbuild can inline `process.env.X` into shipped JS if you reference it from frontend code
- **Error pages** in dev mode (Next.js, Rails, Django) sometimes render env on stack traces
- **Process dumps / coredumps** — dotsec calls `setrlimit(RLIMIT_CORE, 0)` for its own process; your application's process is its own responsibility
- **Shell history** — `export SECRET=xxx && app` puts the secret in history
- **`docker inspect <container>`** — shows env vars to anyone with docker socket access
- **`kubectl get pod -o yaml`** — same for Kubernetes
- **Compromised dependencies running in the same process** — once env vars are set, anyone in that process can read them

dotsec doesn't claim to defend against any of these. They're your responsibility (or your runtime's). The mitigation patterns are well-known — scrub env from crash-report payloads, avoid `process.env.X` references in frontend bundles, prefer Kubernetes Secrets over plain env where supported, redact in your log formatter — but they live in your application and ops layer, not in dotsec.

## Entry names are visible

Even with every value encrypted, the *names* of your secrets are plaintext in the `.sec` file:

```
# @encrypt
STRIPE_SECRET_KEY=ENC[...]

# @encrypt
OPENAI_API_KEY=ENC[...]

# @encrypt
JWT_SIGNING_KEY=ENC[...]
```

Anyone reading the file learns that you use Stripe, OpenAI, and JWTs, and they learn the count and rough shape of your secret architecture. For most teams this is fine — the names are derivable from your code anyway, your package.json lists Stripe and OpenAI SDKs. For teams where the *fact of using* a particular vendor is itself sensitive, give entries opaque names (`API_KEY_1`, `THIRD_PARTY_AUTH_42`) and remap inside your app. This hurts readability for everyone including you; only do it when you have to.

## Assumptions

- **dotsec defends data at rest, not at runtime.** See [above](#what-dotsec-solves-and-what-it-doesnt).
- **dotsec can't stop same-user code from clobbering `.sec.key`.** Use the KMS provider if that's in your threat model — no key file.
- **Key compromise ends the story.** An attacker holding both the file and the private key (or `kms:Decrypt` rights) reads everything. There is no defense-in-depth below the key.
- **`panic = "abort"` skips destructor-based memory wipe.** Two layers defend against the resulting coredump exposure: the fuzz harness keeps the input-driven panic surface closed, and `dotsec` calls `setrlimit(RLIMIT_CORE, 0)` at startup so a panic can't drop a dump containing in-flight secrets in the first place.
- **`dotsec migrate` executes the v4 config.** A `dotsec.config.{ts,js}` is code; migrating runs it. Only migrate configs you trust — see [the migrate command](/guide/commands#dotsec-migrate).
- **dotsec is one layer of a layered supply-chain posture.** Lockfiles, pinned action SHAs, npm provenance, dependency review, secret scanning, SBOM publication — none of those are replaced by dotsec. Treat dotsec as the encrypted-at-rest layer and own the rest of the stack separately.

## Engineering posture

- **Fuzzing.** The parser surface that consumes untrusted `.sec` content (grammar, `@dotsec(...)` header, schema files, parse→render round-trip) is covered by four `cargo-fuzz` targets with curated seed corpora — see `fuzz/` in the repo.
- **Dependency audit.** CI runs `cargo audit` on every push; ignores live in `.cargo/audit.toml`, each with a written rationale.
- **Memory hygiene.** DEKs, decrypted values, and key-file contents are wrapped in `Zeroizing` at the moment secret material enters them, so every exit path (including errors) wipes them.
- **Constant-time comparisons** for the file MAC and the key commitment (via `subtle`).
- **No secrets over FFI.** The `@dotsec/core` Node bindings expose parsing, validation, and formatting only — no decrypt, no key material crosses the boundary.

## Audit and maturity

Honest disclosure, because security-conscious adopters ask:

**What we have.** The age and AES-256-GCM primitives themselves are well-audited (age had a [Cure53 review in 2021](https://age-encryption.org/)). The dotsec wire format on top of them — the canonical serialization, MAC scope, schema-hash binding — is specified in source-as-spec form: `dotsec-core/src/header_v3.rs` documents the directive shape, `crypto/src/mac.rs` documents the canonical bytes the MAC covers. The parser surface that consumes untrusted `.sec` content is fuzzed by four `cargo-fuzz` targets running nightly in CI. Memory hygiene (zeroize on every error path), constant-time MAC comparison (via `subtle`), and panic-time coredump suppression (`setrlimit(RLIMIT_CORE, 0)`) are documented above.

**What we don't have.** No independent cryptographic audit of the dotsec wire format yet. No published test vectors as a stand-alone artifact (they exist as unit tests in `crypto/src/mac.rs` but aren't packaged for cross-implementation verification). The project is a single-maintainer Rust rewrite that hit v7 in 2026; it does not have the "deployed at scale for five years across thousands of teams" maturity that some adopters require.

**Context for the comparison everyone makes.** [Mozilla SOPS](https://github.com/getsops/sops) is older, more widely deployed, and addresses the same broad category (encrypted secrets in git, with KMS/age wrapping). The honest positioning is:

- **SOPS** is the choice when you need multi-cloud (sops wraps the same DEK to AWS KMS *and* GCP KMS *and* age *and* PGP in one file), polyglot file formats (YAML, JSON, ENV, INI, binary), and a mature ecosystem with helm/terraform/kustomize plugins.
- **dotsec** is the choice when you're `.env`-shaped, want schema-driven validation with zero-runtime TypeScript codegen, prefer `dotsec run -- <cmd>` runtime injection over SDKs, and want the AWS-native pattern (KMS encryption context, CloudTrail per-decrypt audit) as a first-class story rather than a plugin.

Different shapes for adjacent problems. For most npm-shaped Node/TS shops on AWS, dotsec fits. For polyglot DevOps shops managing YAML/JSON config across clouds, SOPS fits better. Pick the tool that matches your shape.

**If "battle-tested" is a hard requirement** — financial services, healthcare, anything compliance-bound on a vendor-maturity matrix — wait, or pick SOPS, or run dotsec in development environments first and revisit for production once your own internal review converges. We'd rather you make an informed choice than a misled one.

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
