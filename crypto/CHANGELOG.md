# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [5.0.0](https://github.com/jpwesselink/dotsec-rs/compare/crypto-v0.5.1...crypto-v5.0.0) - 2026-05-13

### Added

- add age-based local key wrapping to crypto crate
- create crypto crate with shared value encryption

### Fixed

- cap age DEK unwrap output and reject oversized wrapped blobs

### Other

- migrate aws crate to use crypto for shared functions
