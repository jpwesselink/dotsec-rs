# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [7.1.0](https://github.com/jpwesselink/dotsec-rs/compare/dotsec-napi-v5.0.0...dotsec-napi-v7.1.0) - 2026-11-08

### Added

- [**breaking**] @push entries no longer injected into env (use @also-env to opt in)

### Fixed

- *(napi)* export generateHeader and hasHeader from @dotsec/core
- *(validate)* file-level @default-encrypt no longer triggers false 'inline @encrypt' errors ([#49](https://github.com/jpwesselink/dotsec-rs/pull/49))

### Other

- release v7.0.1 ([#48](https://github.com/jpwesselink/dotsec-rs/pull/48))
- bump workspace to 7.0.0 ([#37](https://github.com/jpwesselink/dotsec-rs/pull/37))
- release v5.0.2
- release v5.0.1 ([#19](https://github.com/jpwesselink/dotsec-rs/pull/19))
- release v5.0.1
- cargo fmt across workspace
