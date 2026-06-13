# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [7.0.0](https://github.com/jpwesselink/dotsec-rs/compare/dotsec-v0.1.0...dotsec-v7.0.0) - 2026-06-13

### Added

- *(set)* --description flag (schema-aware) ([#25](https://github.com/jpwesselink/dotsec-rs/pull/25))
- KMS EncryptionContext + redact @encrypt validation errors + helper tests ([#35](https://github.com/jpwesselink/dotsec-rs/pull/35))
- [**breaking**] v3 wire format with file-level integrity tag ([#23](https://github.com/jpwesselink/dotsec-rs/pull/23))
- auto-add *.key to .gitignore on keypair creation (--no-gitignore to opt out)
- *(poster)* multi-line quick-start with local + AWS examples
- bump chromakopia to 0.2.0-pr-7 + brand-poster no-args screen
- dotsec set --also-env flag + interactive nudge
- [**breaking**] @push entries no longer injected into env (use @also-env to opt in)
- plasma effect on license command (custom sine-wave interference renderer)
- add license command with rainbow animation
- DX improvements — command order, run --env-file, init nudges
- add quick start + docs link to --help, fix not-found error message
- auto-init with local provider on first dotsec set
- support local provider in dotsec init with age keypair generation
- wire up local encrypt/decrypt dispatch in dotsec-core
- DX improvements — rename eject, set -y, unified schema export, better parse errors
- stamp header in init, import, and migrate
- add dotsec header command
- schema files, constraint directives, codegen, and multi-env support ([#8](https://github.com/jpwesselink/dotsec-rs/pull/8))
- add push command for SSM and Secrets Manager ([#7](https://github.com/jpwesselink/dotsec-rs/pull/7))
- migrate command for dotsec v4 → v5 ([#6](https://github.com/jpwesselink/dotsec-rs/pull/6))
- per-value envelope encryption with AAD, key commitment, and padding
- diff auto-reference, import -y, parser hyphens, masked secrets
- add NAPI bindings (@dotsec/core) ([#3](https://github.com/jpwesselink/dotsec-rs/pull/3))
- rewrite dotsec CLI in Rust

### Fixed

- dotsec -v prints version; CI bakes resolved version into binary
- dotsec run no longer drops bytes at PTY chunk boundaries
- dotsec run inherits the invocation cwd
- pin tsx to major version 4 in v4 migration runner
- do not write decrypted secrets to .sec on rewrite commands
- subcommand_matches panics on alias name — use primary name only
- replace fake dotsec.dev URLs with real github.io URL, fix header example in encryption docs
- clippy warnings — type alias for DekPair, format string
- use write_sec_file for schema file writes consistently
- update empty-value tests and import to struct-style Line variants
- eliminate mixed directive state — schema xor inline, never both
- unknown encryption provider must error, not silently disable
- post-merge review regressions and findings
- comprehensive codebase review, security hardening, and type design ([#11](https://github.com/jpwesselink/dotsec-rs/pull/11))
- use AWS_REGION env var as default in region prompt

### Other

- bump workspace to 7.0.0 ([#37](https://github.com/jpwesselink/dotsec-rs/pull/37))
- hide 3D tilt on home cards + align CLI poster tagline ([#36](https://github.com/jpwesselink/dotsec-rs/pull/36))
- *(poster)* drop confusing inline # comments from quick-start lines
- release v5.0.2
- restore clap default version flag (-V / --version only)
- release v5.0.1 ([#19](https://github.com/jpwesselink/dotsec-rs/pull/19))
- release v5.0.1
- add SAFETY comments to terminal signal + ioctl unsafe blocks
- cargo fmt across workspace
- update plasma TODO with pr-7 API
- note plasma TODO for chromakopia native effect
- upgrade chromakopia beta → stable 0.1.0
- add CLI npm README, fix @dotsec/core README (toJson format, directives, local provider)
- Merge pull request #10 from jpwesselink/fix/empty-values
- release v5.0.0
- Align CI/CD with release-playground, add rspress docs ([#1](https://github.com/jpwesselink/dotsec-rs/pull/1))
- wip

## [5.0.1](https://github.com/jpwesselink/dotsec-rs/compare/dotsec-v0.1.0...dotsec-v5.0.1) - 2026-05-13

### Added

- plasma effect on license command (custom sine-wave interference renderer)
- add license command with rainbow animation
- DX improvements — command order, run --env-file, init nudges
- add quick start + docs link to --help, fix not-found error message
- auto-init with local provider on first dotsec set
- support local provider in dotsec init with age keypair generation
- wire up local encrypt/decrypt dispatch in dotsec-core
- DX improvements — rename eject, set -y, unified schema export, better parse errors
- stamp header in init, import, and migrate
- add dotsec header command
- schema files, constraint directives, codegen, and multi-env support ([#8](https://github.com/jpwesselink/dotsec-rs/pull/8))
- add push command for SSM and Secrets Manager ([#7](https://github.com/jpwesselink/dotsec-rs/pull/7))
- migrate command for dotsec v4 → v5 ([#6](https://github.com/jpwesselink/dotsec-rs/pull/6))
- per-value envelope encryption with AAD, key commitment, and padding
- diff auto-reference, import -y, parser hyphens, masked secrets
- add NAPI bindings (@dotsec/core) ([#3](https://github.com/jpwesselink/dotsec-rs/pull/3))
- rewrite dotsec CLI in Rust

### Fixed

- pin tsx to major version 4 in v4 migration runner
- do not write decrypted secrets to .sec on rewrite commands
- subcommand_matches panics on alias name — use primary name only
- replace fake dotsec.dev URLs with real github.io URL, fix header example in encryption docs
- clippy warnings — type alias for DekPair, format string
- use write_sec_file for schema file writes consistently
- update empty-value tests and import to struct-style Line variants
- eliminate mixed directive state — schema xor inline, never both
- unknown encryption provider must error, not silently disable
- post-merge review regressions and findings
- comprehensive codebase review, security hardening, and type design ([#11](https://github.com/jpwesselink/dotsec-rs/pull/11))
- use AWS_REGION env var as default in region prompt

### Other

- release v5.0.1
- add SAFETY comments to terminal signal + ioctl unsafe blocks
- cargo fmt across workspace
- update plasma TODO with pr-7 API
- note plasma TODO for chromakopia native effect
- upgrade chromakopia beta → stable 0.1.0
- add CLI npm README, fix @dotsec/core README (toJson format, directives, local provider)
- Merge pull request #10 from jpwesselink/fix/empty-values
- release v5.0.0
- Align CI/CD with release-playground, add rspress docs ([#1](https://github.com/jpwesselink/dotsec-rs/pull/1))
- wip

## [5.0.0](https://github.com/jpwesselink/dotsec-rs/compare/dotsec-v0.1.0...dotsec-v5.0.0) - 2026-03-16

### Added

- diff auto-reference, import -y, parser hyphens, masked secrets
- add NAPI bindings (@dotsec/core) ([#3](https://github.com/jpwesselink/dotsec-rs/pull/3))
- rewrite dotsec CLI in Rust

### Other

- Align CI/CD with release-playground, add rspress docs ([#1](https://github.com/jpwesselink/dotsec-rs/pull/1))
- wip
