# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions are computed automatically from git commit history via `scripts/auto-version.sh`.

## [Unreleased]

### Added
- QOS JSON (v2) manifest envelope parsing, hashed via QOS canonical JSON per the [qos_json spec](https://github.com/tkhq/qos/blob/main/src/qos_json/SPEC.md), and rejects duplicate keys, unknown fields, and non-`"v2"` versions

### Removed
- **Breaking:** legacy Borsh QoS manifest decode path. Only QOS JSON (v2) manifest envelopes are decoded (a raw manifest without an envelope is still hash-compared against UserData). Removed `manifest.ManifestVersion` (`V1`/`V2`), the V1 manifest types, `DecodeRawManifestFrom*`, `DecodeManifestFrom*`, `DetectEnvelopeFormat`, and `api.SignablePayloadResponse.ManifestVersion`. `DecodeManifestEnvelopeFrom*` no longer take a version argument.
- `decode-manifest raw` subcommand and the `--api-version` flag on `decode-manifest envelope`
- **Breaking:** `parse` JSON output no longer includes `manifestVersion`
- **Breaking:** `verify --api-version` only accepts `v2`

### Changed
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
