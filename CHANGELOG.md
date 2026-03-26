# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Version information (`--version` flag) with build metadata
- goreleaser configuration for cross-platform binary releases
- GitHub Actions release workflow triggered on version tags
- CHANGELOG.md

## [0.1.0]

### Added
- Transaction parsing and attestation extraction (`parse` command)
- Attestation verification with AWS Nitro Enclave support (`verify` command)
- QoS manifest decoding (`decode` command)
- Attestation document retrieval (`attestation` command)
- ECDSA P-256 request signing
- Boot proof metadata exposure from Turnkey API
- CI pipeline with 80% coverage threshold
