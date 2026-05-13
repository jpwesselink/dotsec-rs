# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
