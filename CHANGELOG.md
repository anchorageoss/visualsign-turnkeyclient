# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions are computed automatically from git commit history via `scripts/auto-version.sh`.

## [Unreleased]

### Added
- NEAR support in `verify`: `--chain CHAIN_NEAR` selects the NEAR decoder for `--include-intermediate-output`, and `--chain-metadata` accepts a `CHAIN_NEAR` variant carrying signed per-asset token mappings keyed by NEAR Intents asset id
- QOS JSON (v2) manifest envelope parsing, alongside the existing Borsh envelope: format is auto-detected (no `--api-version` change required), hashed via QOS canonical JSON per the [qos_json spec](https://github.com/tkhq/qos/blob/main/src/qos_json/SPEC.md), and rejects duplicate keys, unknown fields, and non-`"v2"` versions

### Changed
- The intermediate-output decoder is selected by the request's chain. Borsh carries no chain tag of its own, so a request that names no chain is read as Solana
- Use commit-count-based auto-versioning derived from git history
- Release workflow triggers on push to `main` (auto-creates tags)
- Version output shows `Version (commit: Hash)`; build date is intentionally not included

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
