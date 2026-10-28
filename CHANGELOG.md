# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions are computed automatically from git commit history via `scripts/auto-version.sh`.

## [Unreleased]

### Added
- `api.SolanaChainMetadata.MaxFeeLamports` (wire key `maxFeeLamports`, sent as a JSON number and accepted as a number or a decimal string): a per-transaction cap on base fee plus priority fee, in lamports. The parser renders the cap in force as a top-level "Max Fee" row, applies a default of 0.1 SOL when the field is absent, and rejects a transaction that commits to more
- `verify.SolanaIntermediateOutput.MaxFeeLamports`, the cap in force, carried as the trailing field of Solana intermediate output schema_version 5, and `verify.SolanaDefaultMaxFeeLamports`, the parser default it holds when the request sent no cap
- `verify.SolanaNativeInstructionDecoder` (`ComputeBudgetOnly`, `JsonParsed`), the parser build's native decoding capability that schema_version 5 places right after the version, surfaced as `SolanaIntermediateOutput.NativeInstructionDecoder`; and `verify.SolanaSimulationErrorSimulationUnsupported` (7), set by a parser built without its simulation feature
- NEAR support in `verify`: `--chain CHAIN_NEAR` selects the NEAR decoder for `--include-intermediate-output`, and `--chain-metadata` accepts a `near` variant carrying signed per-asset token mappings keyed by NEAR Intents asset id
- QOS JSON (v2) manifest envelope parsing, hashed via QOS canonical JSON per the [qos_json spec](https://github.com/tkhq/qos/blob/main/src/qos_json/SPEC.md), and rejects duplicate keys, unknown fields, and non-`"v2"` versions

### Removed
- **Breaking:** legacy Borsh QoS manifest decode path. Only QOS JSON (v2) manifest envelopes are decoded (a raw manifest without an envelope is still hash-compared against UserData). Removed `manifest.ManifestVersion` (`V1`/`V2`), the V1 manifest types, `DecodeRawManifestFrom*`, `DecodeManifestFrom*`, `DetectEnvelopeFormat`, and `api.SignablePayloadResponse.ManifestVersion`. `DecodeManifestEnvelopeFrom*` no longer take a version argument.
- `decode-manifest raw` subcommand and the `--api-version` flag on `decode-manifest envelope`
- **Breaking:** `parse` JSON output no longer includes `manifestVersion`
- **Breaking:** `verify --api-version` only accepts `v2`

### Changed
- **Breaking:** Solana intermediate output schema_version 5 (visualsign-parser #625): a `native_instruction_decoder` tag follows the version and `max_fee_lamports` trails the previous layout. `verify.SolanaIntermediateSchemaVersion` is 5 and `DecodeSolanaIntermediateOutput` accepts exactly that version (and refuses an unknown decoder tag), so a consumer of this release and the parser must move together
- **Breaking:** the Solana `metadataDigest` covers the trailing `max_fee_lamports` field of the Borsh-encoded `ChainMetadata`, so every Solana request that carries `chain_metadata` hashes differently from a parser without #625, even when the field is absent. This client against an older parser fails closed on the digest check for such requests, and the previous client against a #625 parser does the same
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
