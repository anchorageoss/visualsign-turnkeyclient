# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions are computed automatically from git commit history via `scripts/auto-version.sh`.

## [Unreleased]

### Changed
- Replaced tag-based semver versioning with commit-count auto-versioning
- Release workflow now triggers on push to `main` (auto-creates tags)
- Removed `Date` from version output (now shows `Version (commit: Hash)`)

### Added
- `scripts/auto-version.sh` for automatic version computation
- Version information (`--version` flag) with build metadata
- goreleaser configuration for cross-platform binary releases
- GitHub Actions release workflow with auto-tagging
- CHANGELOG.md

## Initial Development

### Added
- Transaction parsing and attestation extraction (`parse` command)
- Attestation verification with AWS Nitro Enclave support (`verify` command)
- QoS manifest decoding (`decode` command)
- Attestation document retrieval (`attestation` command)
- ECDSA P-256 request signing
- Boot proof metadata exposure from Turnkey API
- CI pipeline with 80% coverage threshold
