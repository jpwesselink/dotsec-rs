# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [7.0.0](https://github.com/jpwesselink/dotsec-rs/compare/dotenv-v0.15.0...dotenv-v7.0.0) - 2026-06-13

### Added

- *(set)* --description flag (schema-aware) ([#25](https://github.com/jpwesselink/dotsec-rs/pull/25))
- KMS EncryptionContext + redact @encrypt validation errors + helper tests ([#35](https://github.com/jpwesselink/dotsec-rs/pull/35))
- [**breaking**] v3 wire format with file-level integrity tag ([#23](https://github.com/jpwesselink/dotsec-rs/pull/23))
- [**breaking**] @push entries no longer injected into env (use @also-env to opt in)
- DX improvements — rename eject, set -y, unified schema export, better parse errors
- schema files, constraint directives, codegen, and multi-env support ([#8](https://github.com/jpwesselink/dotsec-rs/pull/8))
- per-value envelope encryption with AAD, key commitment, and padding
- diff auto-reference, import -y, parser hyphens, masked secrets
- rewrite dotsec CLI in Rust

### Fixed

- TypeScript codegen safety for non-identifier keys + escaped values
- update empty-value tests and import to struct-style Line variants
- error on inline directives for ALL entries when schema exists
- eliminate mixed directive state — schema xor inline, never both
- unknown encryption provider must error, not silently disable
- post-merge review regressions and findings
- comprehensive codebase review, security hardening, and type design ([#11](https://github.com/jpwesselink/dotsec-rs/pull/11))
- preserve comments during format reorder ([#9](https://github.com/jpwesselink/dotsec-rs/pull/9))

### Other

- bump workspace to 7.0.0 ([#37](https://github.com/jpwesselink/dotsec-rs/pull/37))
- release v5.0.2
- release v5.0.1 ([#19](https://github.com/jpwesselink/dotsec-rs/pull/19))
- release v5.0.1
- cargo fmt across workspace
- Merge pull request #10 from jpwesselink/fix/empty-values
- release v5.0.0
- wip

## [5.0.1](https://github.com/jpwesselink/dotsec-rs/compare/dotenv-v0.15.0...dotenv-v5.0.1) - 2026-05-13

### Added

- DX improvements — rename eject, set -y, unified schema export, better parse errors
- schema files, constraint directives, codegen, and multi-env support ([#8](https://github.com/jpwesselink/dotsec-rs/pull/8))
- per-value envelope encryption with AAD, key commitment, and padding
- diff auto-reference, import -y, parser hyphens, masked secrets
- rewrite dotsec CLI in Rust

### Fixed

- TypeScript codegen safety for non-identifier keys + escaped values
- update empty-value tests and import to struct-style Line variants
- error on inline directives for ALL entries when schema exists
- eliminate mixed directive state — schema xor inline, never both
- unknown encryption provider must error, not silently disable
- post-merge review regressions and findings
- comprehensive codebase review, security hardening, and type design ([#11](https://github.com/jpwesselink/dotsec-rs/pull/11))
- preserve comments during format reorder ([#9](https://github.com/jpwesselink/dotsec-rs/pull/9))

### Other

- release v5.0.1
- cargo fmt across workspace
- Merge pull request #10 from jpwesselink/fix/empty-values
- release v5.0.0
- wip

## [5.0.0](https://github.com/jpwesselink/dotsec-rs/compare/dotenv-v0.15.0...dotenv-v5.0.0) - 2026-03-16

### Added

- diff auto-reference, import -y, parser hyphens, masked secrets
- rewrite dotsec CLI in Rust

### Other

- wip
