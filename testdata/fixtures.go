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
// real Borsh-encoded Solana intermediate output (schema_version 5; the
// request sent no cap, so its trailing MaxFeeLamports is the parser default)
// plus the enclave-signed message digest, used to cross-check the Go Borsh
// decode and signed-digest recompute against Rust output.
//
//go:embed solana_intermediate_sample.json
var SolanaIntermediateSampleJSON []byte

// SolanaIntermediateSimulatedSampleJSON captures a real mainnet Kamino Vault
// transaction with its simulateTransaction result (14 simulated inner
// instructions at this capture, the count following vault state; a mix of
// Preset and Native RegisteredSource, where the Native RPC-parsed SPL Token
// calls also carry a native ParsedInstructionData). The request carried the
// simulation (kept as simulatedTransactionResultB64, exactly as sent) and no
// cap, so the metadataDigest covers an absent max_fee_lamports and the
// output's MaxFeeLamports is the parser default.
//
//go:embed solana_intermediate_simulated_sample.json
var SolanaIntermediateSimulatedSampleJSON []byte

// SolanaIntermediateJSONParsedSampleJSON is real parser_cli v5 output for a
// Compute Budget instruction plus a System transfer: both carry
// SolanaJSONParsedData and a native ParsedInstructionData (empty IdlSource),
// and the trailing MaxFeeLamports is the parser default. Unsigned; it pins
// the decode layout only.
//
//go:embed solana_intermediate_json_parsed_sample.json
var SolanaIntermediateJSONParsedSampleJSON []byte

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

// QosManifestEnvelopeV2JSON is a synthetic QoS JSON (v2) manifest envelope
// fixture. Values are placeholder bytes, not a real captured attestation;
// replacing this with a real captured dev attestation vector is a follow-up.
//
//go:embed qos_manifest_envelope_v2.json
var QosManifestEnvelopeV2JSON []byte

// QosManifestEnvelopeV2CanonicalJSON is the expected QOS canonical JSON bytes
// of QosManifestEnvelopeV2JSON's embedded manifest.
//
//go:embed qos_manifest_envelope_v2_canonical.json
var QosManifestEnvelopeV2CanonicalJSON []byte
