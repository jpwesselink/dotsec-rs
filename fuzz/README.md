# dotsec-rs fuzzing

Four `cargo-fuzz` targets covering the untrusted-input surface: a tampered
`.sec` file is fully attacker-controlled, so every parse path must be total
(no panics, no hangs, no OOM).

| Target          | What it hits                                              | Invariant |
|-----------------|-----------------------------------------------------------|-----------|
| `parse_dotenv`  | Top-level `.sec` grammar + `parse_directive` unwraps      | never panics |
| `parse_header`  | `HeaderV3::parse_inner`: base64 DEK/MAC decode, field validation | never panics / OOMs |
| `parse_schema`  | Schema-file entry point (`Rule::schema`)                  | never panics |
| `roundtrip`     | `parse → render → parse` idempotency                      | render is a faithful inverse |

`roundtrip` is the one that catches *silent corruption* rather than crashes —
a value that mutates across a render cycle would survive an encrypt→decrypt→write
round-trip in a changed form. That's the bug class worth losing sleep over.

## Setup

```sh
cargo install cargo-fuzz          # one-time, needs nightly
rustup toolchain install nightly  # libfuzzer needs nightly

# Seed the live corpus from the curated bootstrap inputs (one-time per
# checkout). `corpus/` is gitignored — it accumulates fuzzer-discovered
# inputs across runs and grows to thousands of files. The hand-curated
# seeds that actually matter live under `seeds/`.
for tgt in parse_dotenv parse_header parse_schema roundtrip; do
  mkdir -p corpus/$tgt && cp seeds/$tgt/* corpus/$tgt/
done
```

## Run

```sh
# Quick smoke — a few minutes each, good for a pre-commit gut-check
cargo +nightly fuzz run parse_dotenv -- -max_total_time=120
cargo +nightly fuzz run parse_header -- -max_total_time=120
cargo +nightly fuzz run parse_schema -- -max_total_time=60
cargo +nightly fuzz run roundtrip    -- -max_total_time=120

# Add a memory cap so a runaway allocation fails loudly instead of swapping
cargo +nightly fuzz run parse_header -- -rss_limit_mb=512 -max_total_time=300
```

A crash drops a reproducer in `fuzz/artifacts/<target>/`. Replay it:

```sh
cargo +nightly fuzz run parse_dotenv fuzz/artifacts/parse_dotenv/crash-<hash>
```

Minimize a corpus once you've run a while:

```sh
cargo +nightly fuzz cmin parse_dotenv
```

## CI

Fuzzing runs in `.github/workflows/fuzz.yml`, not on pull requests:

- **Schedule:** nightly at 04:00 UTC, plus manual runs via `workflow_dispatch`.
- **Per target:** each of the four targets runs as its own matrix job for
  600 seconds (`-max_total_time=600 -rss_limit_mb=512`).
- **Corpus:** `fuzz/corpus/<target>` is cached between runs, and the curated
  seeds from `fuzz/seeds/<target>/` are merged into it on every run.
- **Crashes:** on failure, `fuzz/artifacts/<target>/` is uploaded as a
  workflow artifact (kept 30 days).

When a crash is fixed, add its minimized reproducer
(`cargo +nightly fuzz tmin <target> <crash-file>`) to `fuzz/seeds/<target>/`
so every later run replays it.

The `roundtrip` invariant also runs on **every PR** on stable Rust:
`dotenv/tests/roundtrip.rs` is a proptest twin of the fuzz target and replays
`fuzz/seeds/roundtrip/`, as part of the normal `cargo test --workspace` in `ci.yml`.

For continuous deep fuzzing (the thing that actually finds the rare bug),
register the repo with OSS-Fuzz once it's public — it's free for open source
and runs your targets indefinitely on Google's infra. That's also a concrete
credibility signal for the threat-model doc: "fuzzed continuously via OSS-Fuzz."
