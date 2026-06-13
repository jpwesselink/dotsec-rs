# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [7.0.0](https://github.com/jpwesselink/dotsec-rs/releases/tag/dotsec-core-v7.0.0) - 2026-06-13

### Added

- *(set)* --description flag (schema-aware) ([#25](https://github.com/jpwesselink/dotsec-rs/pull/25))
- KMS EncryptionContext + redact @encrypt validation errors + helper tests ([#35](https://github.com/jpwesselink/dotsec-rs/pull/35))
- [**breaking**] v3 wire format with file-level integrity tag ([#23](https://github.com/jpwesselink/dotsec-rs/pull/23))
- bump chromakopia to 0.2.0-pr-7 + brand-poster no-args screen
- [**breaking**] @push entries no longer injected into env (use @also-env to opt in)
- wire up local encrypt/decrypt dispatch in dotsec-core
- add EncryptionEngine::Local variant and LocalEncryptionOptions
- add generate_header and has_header to dotsec-core
- per-value envelope encryption with AAD, key commitment, and padding
- add NAPI bindings (@dotsec/core) ([#3](https://github.com/jpwesselink/dotsec-rs/pull/3))

### Fixed

- stamp full major.minor.patch in .sec header, not just major
- stamp current major in .sec file headers (was hardcoded "v5")
- prevent symlink-following file writes (overwrite + plaintext leak)
- do not write decrypted secrets to .sec on rewrite commands
- local decrypt now discovers sibling .sec.key file
- remove dead #getting-started anchor from repo URL in header
- clippy warnings — type alias for DekPair, format string
- unknown encryption provider must error, not silently disable
- post-merge review regressions and findings
- comprehensive codebase review, security hardening, and type design ([#11](https://github.com/jpwesselink/dotsec-rs/pull/11))

### Other

- bump workspace to 7.0.0 ([#37](https://github.com/jpwesselink/dotsec-rs/pull/37))
- release v5.0.2
- release v5.0.1 ([#19](https://github.com/jpwesselink/dotsec-rs/pull/19))
- release v5.0.1
- cargo fmt across workspace
- local encryption roundtrip and wrong-key tests
- release v5.0.0

## [5.0.1](https://github.com/jpwesselink/dotsec-rs/releases/tag/dotsec-core-v5.0.1) - 2026-05-13

### Added

- wire up local encrypt/decrypt dispatch in dotsec-core
- add EncryptionEngine::Local variant and LocalEncryptionOptions
- add generate_header and has_header to dotsec-core
- per-value envelope encryption with AAD, key commitment, and padding
- add NAPI bindings (@dotsec/core) ([#3](https://github.com/jpwesselink/dotsec-rs/pull/3))

### Fixed

- prevent symlink-following file writes (overwrite + plaintext leak)
- do not write decrypted secrets to .sec on rewrite commands
- local decrypt now discovers sibling .sec.key file
- remove dead #getting-started anchor from repo URL in header
- clippy warnings — type alias for DekPair, format string
- unknown encryption provider must error, not silently disable
- post-merge review regressions and findings
- comprehensive codebase review, security hardening, and type design ([#11](https://github.com/jpwesselink/dotsec-rs/pull/11))

### Other

- release v5.0.1
- cargo fmt across workspace
- local encryption roundtrip and wrong-key tests
- release v5.0.0

## [5.0.0](https://github.com/jpwesselink/dotsec-rs/releases/tag/dotsec-core-v5.0.0) - 2026-03-16

### Added

- add NAPI bindings (@dotsec/core) ([#3](https://github.com/jpwesselink/dotsec-rs/pull/3))
