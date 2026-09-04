// Package testdata provides embedded test fixtures for use across all test packages.
package testdata

import _ "embed"

// ManifestBin is the real production manifest binary used for testing
//
//go:embed manifest.bin
var ManifestBin []byte

// AttestationBase64 is the real production attestation document in base64 format
//
//go:embed turnkey-attestation.base64
var AttestationBase64 []byte

// SolanaIntermediateSampleJSON is a captured local-parser response carrying a
// real Borsh-encoded Solana intermediate output plus the enclave-signed
// message digest, used to cross-check the Go Borsh decode and signed-digest
// recompute against Rust output.
//
//go:embed solana_intermediate_sample.json
var SolanaIntermediateSampleJSON []byte

// SolanaIntermediateSimulatedSampleJSON captures a real mainnet Kamino Lend
// leveraged deposit-and-borrow transaction with a caller-supplied
// simulateTransactionResult (15 simulated inner instructions, a mix of
// Preset/Native/Unregistered RegisteredSource).
//
//go:embed solana_intermediate_simulated_sample.json
var SolanaIntermediateSimulatedSampleJSON []byte

// SolanaIntermediateGatewayResponseJSON is the full Turnkey-shaped response the
// local parser gateway returned for SolanaIntermediateUnsignedPayload with
// include_intermediate_output=true (mock boot proof + real app signature +
// base64 intermediateOutput). Used for the end-to-end verify test.
//
//go:embed solana_intermediate_gateway_response.json
var SolanaIntermediateGatewayResponseJSON []byte

// SolanaIntermediateUnsignedPayload is the base64 unsigned payload that produced
// SolanaIntermediateGatewayResponseJSON (a 2-signature native SOL transfer).
//
//go:embed solana_intermediate_unsigned_payload.txt
var SolanaIntermediateUnsignedPayload []byte
