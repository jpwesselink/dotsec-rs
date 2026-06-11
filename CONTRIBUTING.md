# Contributing

## Workspace layout

```
dotsec-core/       Core library (encryption, decryption, interpolation, redaction)
dotsec/            CLI binary (uses dotsec-core)
  npm/             npm platform packages
dotsec-napi/       Node.js bindings (published as @dotsec/core)
  npm/             npm platform packages
dotenv/            .env/.sec parser (internal)
crypto/            Shared cryptography + local age encryption (internal)
aws/               AWS KMS encryption + push (internal)
fuzz/              cargo-fuzz targets (standalone crate, not a workspace member)
```

## Build and test

```bash
cargo build --workspace --all-targets
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

CI gates on all four, plus `cargo audit` (ignores with rationales live in `.cargo/audit.toml`).

### KMS integration test (LocalStack)

The `generate_data_key` / `unwrap_data_key` round-trip runs against real KMS semantics via [LocalStack](https://localstack.cloud/). It's `#[ignore]`-gated because it needs Docker:

```bash
cargo test -p aws --test localstack_kms -- --ignored --nocapture
```

Covers: round-trip with matching encryption context, rejection on context mismatch, rejection on missing context.

### Fuzzing

Four `cargo-fuzz` targets cover the untrusted-input surface (a tampered `.sec` file is attacker-controlled, so every parse path must be total). The fuzz crate is standalone — it needs nightly and `libfuzzer-sys`, which stay out of the main build:

```bash
cargo install cargo-fuzz
rustup toolchain install nightly

cd fuzz
# Seed the live corpus from curated inputs (one-time per checkout)
for tgt in parse_dotenv parse_header parse_schema roundtrip; do
  mkdir -p corpus/$tgt && cp seeds/$tgt/* corpus/$tgt/
done

cargo +nightly fuzz run parse_dotenv -- -max_total_time=120
```

See `fuzz/README.md` for the full target list and crash-reproducer workflow.

## Commit conventions

Versioning is automated through [conventional commits](https://www.conventionalcommits.org/) and [release-plz](https://release-plz.ieni.dev/):

| Commit | Bump |
|--------|------|
| `fix: handle empty values` | patch (`6.0.0` → `6.0.1`) |
| `feat: add push command` | minor (`6.0.0` → `6.1.0`) |
| `feat!: redesign directive syntax` | major (`6.0.0` → `7.0.0`) |

A `BREAKING CHANGE:` footer in any commit body also forces a major bump.

## Release workflow

Distribution is **npm-only** — see [why](#why-no-cratesio) below.

### Channels

| Channel | Trigger | npm tag | Version format |
|---|---|---|---|
| **stable** | Release PR merge → GitHub release event | `latest` | `{version}` |
| **beta** | Every push to `main` | `beta` | `{next-version}-beta.{sha}` |
| **branch** | Every PR commit | `<branch-slug>` | `{next-version}-<branch-slug>.{sha}` |

`{next-version}` for prereleases is auto-resolved: if the current `Cargo.toml` version is already published on npm, the publish workflow patch-bumps it before tagging (so a PR opened after `v6.0.0` publishes as `6.0.1-<branch-slug>.<sha>`, not colliding with `6.0.0`). If `Cargo.toml` has been pre-bumped — e.g. a release-prep commit — it's used verbatim.

Prerelease binaries report the prerelease version in `dotsec --version`: each matrix Build job syncs all six workspace `Cargo.toml`s to the resolved version before `cargo build`, so `CARGO_PKG_VERSION` baked into the binary matches the npm tag.

### How a release happens

1. Conventional commits land on `main` (`feat:`, `fix:`, `feat!:`).
2. release-plz opens (or updates) a "chore: release vX.Y.Z" PR with bumped versions across the `dotsec` version_group (all six workspace crates) plus per-crate CHANGELOG entries.
3. You squash-merge the PR. The head commit's `chore: release v…` prefix triggers the release-plz `release` job.
4. The release job creates per-crate git tags (`dotsec-vX.Y.Z`, `dotsec-core-vX.Y.Z`, `dotenv-vX.Y.Z`, `aws-vX.Y.Z`, `crypto-vX.Y.Z`) and matching GitHub releases. No crates.io publish happens — every crate is `publish = false` in `release-plz.toml`.
5. The `dotsec-v…` GitHub release event triggers `publish-npm.yml`; the `dotsec-core-v…` route is covered by `publish-napi.yml`. Both build per-platform native binaries, pack the npm matrix, and push `dotsec@latest` and `@dotsec/core@latest`.

### CI workflows

| Workflow | File | Description |
|---|---|---|
| **CI** | `ci.yml` | Runs on every push and PR. Gates: `cargo fmt --all -- --check`, `cargo build --workspace --all-targets`, `cargo test --workspace --all-targets`, `cargo clippy --workspace --all-targets -- -D warnings`, and a separate `cargo audit` job |
| **Publish CLI to NPM** | `publish-npm.yml` | Builds the CLI binary for 6 platforms, packs the npm matrix, publishes `dotsec`. Triggered by push-to-main (beta tag), release event (latest tag), or `workflow_dispatch` |
| **Publish Core npm package** | `publish-napi.yml` | Same shape as above for the NAPI bindings; publishes `@dotsec/core` |
| **Deploy docs** | `deploy-docs.yml` | Builds and deploys docs to GitHub Pages. Versioned subdirectories: `/v{X.Y.Z}/` (release event), `/beta/` (main push), `/pr-{N}/` (PR commit) |
| **Release-plz** | `release-plz.yml` | Analyzes conventional commits since the last tag. On push to `main`, opens or updates a release PR. When a `chore: release v…` commit lands, runs the release job (tags + GitHub releases) |

### Why no crates.io

The obvious crate names on crates.io — `dotsec`, `crypto`, `dotenv`, `aws` — are owned by unrelated projects from before dotsec-rs existed. Renaming the Rust crates to publishable names is on the backlog but doesn't change the user-facing distribution story: users always get dotsec via `npm install -g dotsec`, which bundles a native per-platform binary built from the Rust source. `dotsec-core` (the NAPI library) is similarly published only as `@dotsec/core` on npm.

## Security issues

Please report suspected vulnerabilities through [GitHub security advisories](https://github.com/jpwesselink/dotsec-rs/security/advisories/new), not public issues.
