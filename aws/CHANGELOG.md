# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [6.0.0](https://github.com/jpwesselink/dotsec-rs/compare/aws-v0.0.1...aws-v6.0.0) - 2026-06-13

### Added

- *(set)* --description flag (schema-aware) ([#25](https://github.com/jpwesselink/dotsec-rs/pull/25))
- KMS EncryptionContext + redact @encrypt validation errors + helper tests ([#35](https://github.com/jpwesselink/dotsec-rs/pull/35))
- [**breaking**] v3 wire format with file-level integrity tag ([#23](https://github.com/jpwesselink/dotsec-rs/pull/23))

## [5.0.1](https://github.com/jpwesselink/dotsec-rs/compare/aws-v0.0.1...aws-v5.0.1) - 2026-05-13

### Added

- schema files, constraint directives, codegen, and multi-env support ([#8](https://github.com/jpwesselink/dotsec-rs/pull/8))
- add push command for SSM and Secrets Manager ([#7](https://github.com/jpwesselink/dotsec-rs/pull/7))
- per-value envelope encryption with AAD, key commitment, and padding
- rewrite dotsec CLI in Rust

### Fixed

- post-merge review regressions and findings
- comprehensive codebase review, security hardening, and type design ([#11](https://github.com/jpwesselink/dotsec-rs/pull/11))

### Other

- release v5.0.1
- cargo fmt across workspace
- migrate aws crate to use crypto for shared functions
- release v5.0.0
- wip

## [5.0.0](https://github.com/jpwesselink/dotsec-rs/compare/aws-v0.0.1...aws-v5.0.0) - 2026-03-16

### Added

- rewrite dotsec CLI in Rust

### Other

- wip
