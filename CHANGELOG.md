# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions are computed automatically from git commit history via `scripts/auto-version.sh`.

## [Unreleased]

### Added
- Solana intermediate output schema_version 5 (visualsign-parser #575): `verify.SolanaNativeInstructionDecoder` (`ComputeBudgetOnly`, `JsonParsed`) mirrors the new `native_instruction_decoder` byte that follows `schema_version`, surfaced as `SolanaIntermediateOutput.NativeInstructionDecoder` (nil for schema_version 4); `SolanaSimulationErrorSimulationUnsupported` (7) mirrors the new simulation-error variant
- `verify.SolanaIntermediateMinSchemaVersion` (4) and `verify.SolanaIntermediateMaxSchemaVersion` (5)
- NEAR support in `verify`: `--chain CHAIN_NEAR` selects the NEAR decoder for `--include-intermediate-output`, and `--chain-metadata` accepts a `near` variant carrying signed per-asset token mappings keyed by NEAR Intents asset id
- QOS JSON (v2) manifest envelope parsing, hashed via QOS canonical JSON per the [qos_json spec](https://github.com/tkhq/qos/blob/main/src/qos_json/SPEC.md), and rejects duplicate keys, unknown fields, and non-`"v2"` versions

### Deprecated
- `verify.SolanaIntermediateSchemaVersion`, now an alias for `SolanaIntermediateMaxSchemaVersion` (5); use the min/max pair and `SolanaIntermediateOutput.SchemaVersion`

### Removed
- **Breaking:** legacy Borsh QoS manifest decode path. Only QOS JSON (v2) manifest envelopes are decoded (a raw manifest without an envelope is still hash-compared against UserData). Removed `manifest.ManifestVersion` (`V1`/`V2`), the V1 manifest types, `DecodeRawManifestFrom*`, `DecodeManifestFrom*`, `DetectEnvelopeFormat`, and `api.SignablePayloadResponse.ManifestVersion`. `DecodeManifestEnvelopeFrom*` no longer take a version argument.
- `decode-manifest raw` subcommand and the `--api-version` flag on `decode-manifest envelope`
- **Breaking:** `parse` JSON output no longer includes `manifestVersion`
- **Breaking:** `verify --api-version` only accepts `v2`

### Changed
- `DecodeSolanaIntermediateOutput` accepts Solana intermediate schema_version 4 through 5, decoding each with its own layout, instead of exactly 4, so the client works against parsers on either side of the schema 5 rollout. Other versions are still refused
- The intermediate-output decoder is selected by `VerifyResponseRequest.Chain`. Borsh carries no chain tag of its own, so `VerifyResponse` now requires `Chain` to decode a non-empty intermediate output rather than assuming Solana
- **Breaking:** `verify.Verify` now requires `VerifyRequest.Chain` and returns an error when it is empty, instead of silently defaulting to `CHAIN_SOLANA`
- **Breaking:** `verify` fails when a QoS manifest is present but the boot attestation UserData is empty, instead of skipping the manifest hash binding
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
