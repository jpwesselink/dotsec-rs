# V3 Wire Format: File-Level MAC + Structured Header Block (F1 + F6)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Source:** Findings F1 (file-level MAC over directives) and F6 (structured header block) from the 2026-05-12 external security review of PR #13. F1 is the S1 (critical) finding; F6 pairs naturally so we bump the wire format only once.

**Goal:** Authenticate all `.sec` file content (directives, key names, encrypted-value bindings, schema reference) under the DEK so that tampering with any plaintext metadata — `@push` targets, `@key-id`, `@type` constraints — invalidates the file. Restructure the file envelope into a dedicated header block to make the on-disk model legible and forward-compatible.

**Non-goals:** AWS `EncryptionContext` (F2 — separate plan, gates on V3). Multi-recipient support (F3 — separate plan). Local key-file location changes (F5 — separate plan).

**Architecture summary:**

- New wire format **V3**, detected via a `#!dotsec format=v3` header line. V2 files remain readable forever, with a deprecation warning on every read.
- File envelope moves out of dotenv KV space into a `#!dotsec key=value` header block parsed before any KV.
- **`__DOTSEC_KEY__`** (Kv line) → **`#!dotsec key=<base64>`** (header line). Same wrapped DEK bytes.
- New **`#!dotsec mac=<base64>`** = HMAC-SHA256(DEK, canonical_serialization(file)). Covers directives, key ordering, plaintext values, and the `ENC[...]` markers themselves (so ciphertext-to-key bindings are MAC-authenticated, not just the AAD-protected plaintext).
- New **`dotsec upgrade-format`** CLI command for opt-in V2→V3 migration.
- Schema interaction: if `dotsec.schema` exists, its SHA-256 content hash is mixed into the MAC's AAD. Schema content is git-tracked; this makes schema-tamper detection a side effect of file-MAC verification.

**Tech stack:** Rust, `hmac` (already a dep via `crypto` crate), `sha2`, `base64`. No new dependencies.

**Threat model recap:** F1 closes three concrete attacks documented in the security review — push redirection, KMS hijack on next rotate, and type-validation bypass. See [section "Attack scenarios"](#attack-scenarios) below for the test cases each scenario produces.

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `crypto/src/lib.rs` | Modify | Add `compute_file_mac` / `verify_file_mac` using HMAC-SHA256 |
| `crypto/src/mac.rs` | Create | Canonical serialization helpers for MAC input |
| `dotsec-core/src/lib.rs` | Modify | V3 detection, header parsing, MAC compute/verify on encrypt/decrypt, threading schema hash |
| `dotsec-core/src/format.rs` | Create | `SecFormat` enum (V1/V2/V3), header block parser/writer |
| `dotenv/src/lib.rs` | Modify | Recognize `#!dotsec` header lines (parsed separately from comments) |
| `dotsec/src/cli/commands/upgrade_format.rs` | Create | New `dotsec upgrade-format` command |
| `dotsec/src/cli/commands/mod.rs` | Modify | Register `upgrade-format` subcommand |
| `dotsec/src/cli/commands/set.rs` | Modify | Write V3 for new files; warn on V2 writes |
| `dotsec/src/cli/commands/rotate_key.rs` | Modify | Re-MAC after DEK rotation |
| `dotsec/src/cli/commands/format.rs` | Modify | Re-MAC after reorder |
| `dotsec/src/cli/commands/remove_directives.rs` | Modify | Re-MAC after directive strip |
| `docs/guide/encryption.md` | Modify | Document V3 format, MAC scope, upgrade flow |
| `docs/guide/commands.md` | Modify | Document `upgrade-format` |
| `docs/superpowers/specs/2026-05-13-v3-format.md` | Create | Wire format spec doc (separate from this plan) |

---

## Wire format V3

A V3 `.sec` file has three regions in order: **header block**, **directive block** (existing `# @directive` comments), **KV block** (existing `KEY=value` lines).

```
#!dotsec format=v3
#!dotsec key=AQIDAH...base64...
#!dotsec mac=base64...

# @provider=aws @key-id=alias/dotsec @region=eu-west-1 @default-encrypt

# @encrypt @type=string
DATABASE_URL=ENC[...]

PORT=3000
```

### Header line grammar

```
header_line = "#!dotsec" SP key "=" value NL
key         = [a-z][a-z0-9-]*
value       = printable bytes except NL
```

Header lines must precede any directive comment or KV line. First non-header line terminates the header block.

**Recognized header keys** (V3 baseline):

| Key | Required | Format | Notes |
|-----|----------|--------|-------|
| `format` | yes | `v3` (literal) | Format discriminator |
| `key` | yes | base64 | Wrapped DEK (replaces `__DOTSEC_KEY__`) |
| `mac` | yes | base64 | HMAC-SHA256(DEK, canonical) |

Unknown header keys are preserved on write and ignored on read (forward compatibility). Reserved future keys: `kms-context` (F2), `recipients` (F3).

### MAC input — canonical serialization

The canonical serialization is the bytes that go into `HMAC-SHA256(DEK, ·)`. It must be deterministic across encrypts of equivalent content and must cover every piece of plaintext that influences runtime behavior.

**Pseudocode:**

```
canonical = b""
canonical += b"dotsec-mac-v3\n"                         # domain-separation tag
canonical += b"schema-sha256=" + hex(schema_hash) + b"\n"
for directive in file_level_directives_sorted:           # @provider, @key-id, @region, ...
    canonical += b"file-directive:" + directive.name + b"=" + directive.value.unwrap_or("") + b"\n"
for entry in entries_in_file_order:                      # preserves order; ordering is part of the MAC
    canonical += b"entry:" + entry.key + b"\n"
    for directive in entry.directives_sorted:
        canonical += b"  directive:" + directive.name + b"=" + directive.value.unwrap_or("") + b"\n"
    if entry.value.starts_with("ENC["):
        canonical += b"  enc:" + entry.value + b"\n"     # binds ciphertext-to-key
    else:
        canonical += b"  plain:" + entry.value + b"\n"   # plaintext values get MAC'd too
```

Notes:
- The domain-separation tag `dotsec-mac-v3` prevents cross-format MAC reuse if we ever introduce v4.
- `schema_hash` = SHA-256(schema file bytes) or SHA-256(b"") if no schema. Deterministic in both cases.
- Per-entry directives are sorted by name within an entry; entries themselves stay in file order (because file order matters — `dotsec format` reorders, and we MAC that reordering).
- Comments, blank lines, and non-`@` whitespace are explicitly **not** included. Reformatting whitespace must not invalidate the MAC.

---

## Migration: V2 → V3

V2→V3 is a lossless transformation. Per-value `ENC[...]` ciphertexts are unchanged. Wrapped DEK bytes are unchanged (for local provider). For AWS-provider files, upgrade is also DEK-preserving in this PR (AWS `EncryptionContext` rewrap lands in F2).

### `dotsec upgrade-format`

```bash
dotsec upgrade-format                    # upgrade --sec-file (default .sec)
dotsec upgrade-format .sec.prod          # explicit file
dotsec upgrade-format --all              # upgrade every .sec* in cwd
dotsec upgrade-format --dry-run          # show V3 output, write nothing
```

Mechanical steps:

1. Read V2 file; refuse if format is V1 (legacy) with a message pointing to migration.
2. Resolve provider config from inline directives.
3. Unwrap DEK using current provider (requires private key for local, `kms:Decrypt` for AWS).
4. Compute schema content hash if `dotsec.schema` discovered.
5. Compute MAC over canonical serialization of the current directive + entry state.
6. Emit V3 layout: header block first (`format=v3`, `key=<unchanged>`, `mac=<new>`), then existing directive comments and KV lines verbatim.
7. Atomic write via temp file + rename. Refuse if file changed under us.

### Read-side compatibility

`detect_format()` extends to three variants:

- **V1**: legacy single-blob format. Already errors with migration message.
- **V2**: `__DOTSEC_KEY__` Kv line present, no `#!dotsec format=` header. Continues to work; one warning per invocation.
- **V3**: `#!dotsec format=v3` header present. MAC required; mismatch is fatal.

V2 deprecation warning:

```
⚠ .sec.prod uses legacy V2 format — directives are not authenticated.
  Run: dotsec upgrade-format    (no re-encryption needed)
  Silence: export DOTSEC_SILENCE_FORMAT_WARNING=1
```

Warning fires once per CLI invocation per file. Silenceable for CI.

### What we explicitly do not do

- No silent format bump on write. A V2 `dotsec set` writes V2; the user runs `upgrade-format` when they're ready to commit the V3 diff.
- No `dotsec downgrade-format`. V2 is reachable by manual file edit if absolutely needed; we don't ship a footgun.
- No re-encryption of values during upgrade. Speed and atomicity matter for adoption.

---

## Attack scenarios (test cases F1 must defeat)

These map 1:1 to the security review's documented attacks. Each gets a regression test.

### Attack 1: push redirection

```diff
- # @push=aws-ssm(path="/myapp/prod/db-password")
+ # @push=aws-ssm(path="/attacker-owned/db-password-mirror")
  DB_PASSWORD=ENC[...unchanged...]
```

**Test:** Encrypt + MAC, then mutate the `@push` directive in-place, then `dotsec push --dry-run` → MAC verify fails. Test name: `v3_push_directive_tamper_fails_mac`.

### Attack 2: KMS hijack on next rotate

```diff
- # @provider=aws @key-id=alias/dotsec @region=eu-west-1 @default-encrypt
+ # @provider=aws @key-id=arn:aws:kms:eu-west-1:ATTACKER:key/abc @region=eu-west-1 @default-encrypt
```

**Test:** Encrypt + MAC, mutate `@key-id`, run `dotsec rotate-key` → MAC verify fails before any KMS call. Test name: `v3_keyid_tamper_blocks_rotate_key`. Critical that rotate-key isn't a silent path around the MAC.

### Attack 3: type-validation bypass

```diff
- # @encrypt @type=enum("development","staging","production")
+ # @encrypt @type=string
  NODE_ENV=ENC[...]
```

**Test:** Encrypt with enum, mutate to string, `dotsec validate` → MAC verify fails before any validation logic runs. Test name: `v3_type_directive_tamper_fails_mac`.

### Attack 4: cross-key ciphertext swap (already covered, regression test)

This is the AAD attack from the existing implementation (key-name-as-AAD). V3 adds a second defense (the `enc:` line in MAC input binds ciphertext literal to key name), so swapping `ENC[...]` between keys now fails at MAC verification too, before reaching AES-GCM. Test name: `v3_enc_swap_between_keys_fails_mac`.

### Attack 5: entry reorder

```diff
  DATABASE_URL=ENC[...A...]
- LOG_LEVEL=ENC[...B...]
+ LOG_LEVEL=ENC[...B...]
  DATABASE_URL=ENC[...A...]
```

**Test:** Reorder entries with `dotsec format` (legitimate) → MAC is recomputed and verifies. Reorder by hand without recomputing → MAC fails. Test name: `v3_manual_reorder_fails_mac`.

### Attack 6: schema tamper

```diff
- @encrypt @type=enum("development","production")
+ @encrypt @type=string
```

(in `dotsec.schema`, not the `.sec` file)

**Test:** Encrypt a `.sec` with schema present, mutate schema, `dotsec validate` → MAC fails because schema hash in AAD changed. Test name: `v3_schema_tamper_invalidates_file_mac`.

---

## Open questions (need user ratification before Task 1)

From section 6 of the security review:

1. **V2→V3 forced or opt-in?** **Recommendation: opt-in via `dotsec upgrade-format`.** Forced silent upgrade churns every consumer's git history on first contact with V3-capable dotsec.
2. **Schema MAC scope?** **Recommendation: schema content hash in the file MAC's AAD.** Schema tamper invalidates every file MAC — correct blast radius, schema is the cross-file source of truth.
3. **Multi-recipient files (mixing AWS + local) in V3?** **Recommendation: forbid in V3.** Premature complexity; revisit in V4 if anyone asks.
4. **`EncryptionContext` key naming (case sensitivity, ordering)?** Confirmed against AWS docs — keys are case-sensitive, IAM conditions match exact key. Lock in `dotsec:file`, `dotsec:repo`, `dotsec:format`. Out of scope for this plan; documented for the F2 follow-up.

---

## Tasks

### Task 1: Canonical serialization + MAC primitives

**Files:**
- Create: `crypto/src/mac.rs`
- Modify: `crypto/src/lib.rs`

- [ ] **Step 1: Create `crypto/src/mac.rs` with the canonical serializer.**
  - Function signature: `pub fn canonical_serialize(file_directives: &[Directive], entries: &[Entry], schema_hash: &[u8; 32]) -> Vec<u8>`.
  - Pure function, no I/O. Deterministic.
  - Internal helper `sort_directives_by_name(...)` for the per-entry directive sort.
  - Domain-separation tag is `b"dotsec-mac-v3\n"` as the first bytes.

- [ ] **Step 2: Add `compute_file_mac` / `verify_file_mac` to `crypto/src/lib.rs`.**
  - `pub fn compute_file_mac(dek: &[u8], canonical: &[u8]) -> [u8; 32]`
  - `pub fn verify_file_mac(dek: &[u8], canonical: &[u8], mac: &[u8]) -> Result<(), CryptoError>`
  - Verify uses constant-time compare via `subtle::ConstantTimeEq`.
  - New error variant: `CryptoError::MacMismatch`.

- [ ] **Step 3: Unit tests.**
  - Round-trip: compute then verify succeeds.
  - Tamper: flip one byte of canonical input → verify fails.
  - Wrong DEK: verify fails.
  - Deterministic: same inputs → same MAC bytes across calls.
  - Sort stability: per-entry directives in different orders produce identical canonical output.

### Task 2: Schema content hashing

**Files:**
- Create: `dotenv/src/schema_hash.rs`
- Modify: `dotenv/src/schema.rs`

- [ ] **Step 1: `pub fn hash_schema_file(path: &Path) -> std::io::Result<[u8; 32]>`.** SHA-256 of the file bytes. No normalization — comments and whitespace are part of the hash. Rationale: simplest possible semantics; if users want schema reformat to not invalidate, they re-MAC after.

- [ ] **Step 2: `pub fn empty_schema_hash() -> [u8; 32]`.** SHA-256 of empty bytes. Used when no schema discovered.

- [ ] **Step 3: Unit tests.**
  - Identical file → identical hash.
  - Modified file → different hash.
  - Missing file → caller responsibility (returns `io::Error`); empty hash is opt-in via `empty_schema_hash()`.

### Task 3: Format detection + header parser

**Files:**
- Create: `dotsec-core/src/format.rs`
- Modify: `dotsec-core/src/lib.rs`
- Modify: `dotenv/src/lib.rs`

- [ ] **Step 1: `SecFormat` enum gains `V3` variant.** Update `detect_format()` to recognize `#!dotsec format=v3` in the header block.

- [ ] **Step 2: Header parser.** `pub fn parse_header(content: &str) -> Result<(Header, &str), HeaderError>` returns the parsed header and the remainder of the file. Header struct:
  ```rust
  pub struct Header {
      pub format: String,           // "v3"
      pub wrapped_dek: Vec<u8>,     // base64-decoded
      pub mac: Vec<u8>,             // base64-decoded, must be 32 bytes
      pub extras: BTreeMap<String, String>,  // unknown keys preserved verbatim
  }
  ```

- [ ] **Step 3: Header writer.** `pub fn write_header(header: &Header) -> String` emits the `#!dotsec` lines in a fixed order (`format` first, then `key`, then `mac`, then alphabetical extras). Order stability matters for git diffs.

- [ ] **Step 4: Update `dotenv::parse_dotenv` to skip header lines without treating them as comments.** Header lines must not appear in `Line::Comment` or anywhere in the standard parse output — they're consumed by the format layer above.

- [ ] **Step 5: Unit tests.**
  - V3 round-trip: parse then write produces byte-identical output.
  - Unknown header key preserved through round-trip.
  - Malformed header (missing required key, invalid base64, wrong MAC length) → clear error.
  - V2 file (no header) → `parse_header` returns sentinel "no header" indicator, not an error.

### Task 4: Wire MAC into encrypt + decrypt paths

**Files:**
- Modify: `dotsec-core/src/lib.rs`

- [ ] **Step 1: `encrypt_lines_to_sec` for V3.**
  - After encrypting all values and generating wrapped DEK:
    1. Compute `schema_hash` (call `hash_schema_file` or `empty_schema_hash`).
    2. Build canonical serialization input from final directive + entry state.
    3. Compute MAC.
    4. Emit V3 file with header block.
  - Default behavior for **new** files: write V3. Default for **existing V2 files**: write V2 (user must opt-in via `upgrade-format`).

- [ ] **Step 2: `decrypt_sec_to_lines` for V3.**
  - Detect format → dispatch.
  - For V3: parse header, unwrap DEK, recompute canonical from on-disk state, compare MAC. Mismatch → `Err("MAC verification failed: directives or values modified after encryption. If intentional, run \`dotsec upgrade-format\` to re-MAC.")`.
  - For V2: existing decrypt path + emit deprecation warning once per invocation (use a `OnceLock` or thread-local).

- [ ] **Step 3: Integration tests.**
  - V3 round-trip: encrypt + decrypt succeeds.
  - All six attack scenarios above produce `MacMismatch` errors.
  - V2 decrypt continues to work (regression test for back-compat).
  - V2 read emits warning to stderr (capture stderr; assert substring).
  - `DOTSEC_SILENCE_FORMAT_WARNING=1` suppresses warning.

### Task 5: `dotsec upgrade-format` command

**Files:**
- Create: `dotsec/src/cli/commands/upgrade_format.rs`
- Modify: `dotsec/src/cli/commands/mod.rs`

- [ ] **Step 1: Subcommand registration.**
  ```rust
  pub fn command() -> Command {
      Command::new("upgrade-format")
          .about("Upgrade .sec file from V2 to V3 (no re-encryption)")
          .arg(Arg::new("files").num_args(0..))
          .arg(Arg::new("all").long("all").action(SetTrue))
          .arg(Arg::new("dry-run").long("dry-run").action(SetTrue))
  }
  ```

- [ ] **Step 2: Execution.**
  - Resolve target files: explicit args, then `--all` glob (`*.sec*` in cwd), then default `--sec-file`.
  - For each file:
    1. Detect format. V1 → error with migration pointer. V3 → "already V3, skipping." V2 → proceed.
    2. Resolve provider config from inline directives.
    3. Unwrap DEK.
    4. Compute MAC.
    5. Emit V3 layout (preserve all existing comments, directives, blank lines verbatim; only the envelope changes).
    6. Atomic write (temp file + `rename`), unless `--dry-run`.
  - Print per-file status: `✓ .sec — V2 → V3` or `→ .sec.prod — already V3`.
  - Summary line: "Upgraded N files. Commit: git add ... && git commit -m '...'".

- [ ] **Step 3: Tests.**
  - Upgrade a V2 local file: V3 file decrypts identically, same wrapped DEK, new MAC.
  - Upgrade a V2 AWS file: same wrapped DEK (F2 rewrap is later), new MAC.
  - `--dry-run`: file unchanged, V3 layout printed to stdout.
  - `--all` with mixed V2/V3 files: V3 files skipped with informational message.
  - Missing key for local: clean error pointing to `DOTSEC_PRIVATE_KEY` or `.sec.key`.
  - V1 file: refuses with migration message.

### Task 6: Re-MAC on mutating commands

**Files:**
- Modify: `dotsec/src/cli/commands/set.rs`
- Modify: `dotsec/src/cli/commands/rotate_key.rs`
- Modify: `dotsec/src/cli/commands/format.rs`
- Modify: `dotsec/src/cli/commands/remove_directives.rs`
- Modify: `dotsec/src/cli/commands/import.rs`

- [ ] **Step 1: Every command that writes back to the `.sec` file must recompute MAC for V3 files.**
  - Centralize the write logic so each command goes through a single `write_sec_with_mac(...)` helper rather than duplicating the encrypt+canonical+MAC dance.
  - V2 files keep V2-style writes (no MAC) — opt-in only.

- [ ] **Step 2: Tests per command.**
  - For each mutating command: after running it, decrypt and verify MAC. Regression target: a forgotten re-MAC site silently produces V3 files with stale MACs.

### Task 7: Documentation

**Files:**
- Modify: `docs/guide/encryption.md`
- Modify: `docs/guide/commands.md`
- Create: `docs/superpowers/specs/2026-05-13-v3-format.md`

- [ ] **Step 1: Encryption guide — add "Format versions" section.**
  - V2 vs V3 table: what each protects, why V3 exists.
  - Resolves the existing `<!-- TODO: "Why age?" -->` block while we're in this file; cover the "Why age?" rationale per the prior TODO note.

- [ ] **Step 2: Commands guide — document `upgrade-format`.**
  - Flags, examples, what to expect in the git diff.
  - Cross-link from `set` / `rotate-key` / `format` sections so users discover it.

- [ ] **Step 3: Wire format spec.**
  - Stable reference document under `docs/superpowers/specs/` describing V3 header grammar, MAC canonical input format, schema-hash semantics, reserved keys.
  - Doubles as the input for any future third-party implementations.

---

## Test fixtures

Create under `dotsec-core/tests/fixtures/`:

- `v2-local.sec` — V2 file encrypted with a known age keypair; decrypts cleanly.
- `v2-local.sec.key` — matching key file.
- `v3-local.sec` — V3 file with valid MAC.
- `v3-local-tampered-push.sec` — V3 file with `@push` directive mutated post-MAC.
- `v3-local-tampered-keyid.sec` — `@key-id` mutated.
- `v3-local-tampered-type.sec` — `@type` enum→string.
- `v3-local-tampered-enc-swap.sec` — `ENC[...]` values swapped between keys.
- `v3-local-tampered-reorder.sec` — entries reordered without re-MAC.
- `v3-local-with-schema.sec` + `dotsec.schema` — for the schema-tamper test (modify schema, decrypt fails).

Fixture generation: a `dev/scripts/generate-v3-fixtures.sh` script that uses the dotsec CLI to produce known-good V3 files, then a Python or Rust tampering helper for the post-write mutations. Commit both the script and the fixtures; CI regenerates on demand to catch drift.

---

## Risks and mitigations

| Risk | Mitigation |
|------|-----------|
| Adoption stall — users ignore the V2 warning forever | Set a removal date for V2 support (e.g., "V2 read support removed in dotsec 7.0, scheduled for 2027"); land that line in CHANGELOG now |
| Diff churn from V3 upgrade in big repos | `dotsec upgrade-format --all` upgrades atomically per file; users commit one batch per repo |
| MAC recomputation forgotten on a new mutating command added later | Centralize via `write_sec_with_mac` helper (Task 6 Step 1); add a `// FIXME: must re-MAC` clippy lint or a comment-based audit checklist in the spec |
| Schema-hash semantics surprise users (formatting schema breaks MAC) | Document loudly in the spec; offer `dotsec re-mac` as a one-command fix without rotating the DEK |
| Atomic write race on Windows | Use `tempfile::NamedTempFile::persist`; document the failure mode if the user has the file open elsewhere |

---

## Out of scope (follow-up PRs)

- **F2**: AWS `EncryptionContext` rewrap on upgrade. Gates on V3 landing. Separate plan.
- **F3**: Multi-recipient. Reserves `#!dotsec recipients=` header key but doesn't implement.
- **F5**: Local key file location enforcement. Independent of format.
- **`dotsec re-mac`**: Convenience command to recompute MAC after intentional directive edits without going through `upgrade-format` or `set`. Useful but not strictly required — `dotsec set <key>` on any existing key triggers a full re-MAC. Defer unless users ask.

---

## Definition of done

- [ ] All seven tasks completed with passing tests.
- [ ] `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] Manual end-to-end smoke test: encrypt → tamper → decrypt fails for each of the six attack scenarios.
- [ ] V2 deprecation warning verified on every read path (`run`, `show`, `validate`, `export`).
- [ ] Wire format spec doc committed.
- [ ] Encryption guide updated with V2/V3 section and resolves the existing "Why age?" TODO.
- [ ] `dotsec upgrade-format` documented with examples.
- [ ] CHANGELOG entry under conventional-commits `feat:` with `BREAKING CHANGE:` footer if V2 deprecation date is published.
