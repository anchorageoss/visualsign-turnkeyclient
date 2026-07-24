// Package api provides a client for Turnkey's Visualsign API.
//
// The client handles:
// - API authentication with ECDSA P-256 keys
// - Request/response marshaling and signing
// - Attestation document retrieval
// - Cryptographic operations for API key authentication
//
// # Usage
//
// Create a client using NewClient with an API key provider:
//
//	client, err := api.NewClient(hostURI, httpClient, organizationID, keyProvider)
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Call CreateSignablePayload to request transaction parsing:
//
//	response, err := client.CreateSignablePayload(ctx, &api.CreateSignablePayloadRequest{
//		UnsignedPayload: "base64-encoded-payload",
//		Chain:           "CHAIN_SOLANA",
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
package api

import (
	"crypto/ecdsa"
	"encoding/json"
	"math/big"

	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
)

// TurnkeyAPIKey represents the API key configuration
type TurnkeyAPIKey struct {
	PublicKey      string
	PrivateKey     *ecdsa.PrivateKey
	OrganizationID string
}

// SignatureKV is a key-value metadata entry attached to an ABISignature.
// Standard keys: "algorithm" ("secp256k1" or "ed25519"), "public_key" (hex),
// "issuer" (address), "timestamp" (unix epoch string).
type SignatureKV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ABISignature is an optional cryptographic signature over an ABI definition.
// Value is the hex-encoded signature over the ABI JSON content.
// Metadata carries algorithm, public key, and any other attestation fields.
// Use NewABISignature to construct with the standard metadata layout.
type ABISignature struct {
	Value    string        `json:"value"`
	Metadata []SignatureKV `json:"metadata,omitempty"`
}

// NewABISignature constructs an ABISignature with the standard metadata fields.
// value is the hex-encoded signature over the ABI JSON string.
// algorithm is the signing algorithm, e.g. "secp256k1" or "ed25519".
// publicKey is the hex-encoded public key of the signer.
// extra adds any additional metadata entries (e.g. "issuer", "timestamp").
func NewABISignature(value, algorithm, publicKey string, extra ...SignatureKV) *ABISignature {
	kvs := make([]SignatureKV, 0, 2+len(extra))
	kvs = append(kvs, SignatureKV{Key: "algorithm", Value: algorithm})
	kvs = append(kvs, SignatureKV{Key: "public_key", Value: publicKey})
	kvs = append(kvs, extra...)
	return &ABISignature{Value: value, Metadata: kvs}
}

// AbiType mirrors parser.proto AbiType. It is sent on the JSON wire as the proto
// enum name (e.g. "ABI_TYPE_PROXY"), matching the parser's serde representation.
// The metadata digest hashes the underlying proto enum number, not this string;
// see borsh.go.
type AbiType string

const (
	// AbiTypeUnspecified is the proto default. The parser treats it as implementation.
	AbiTypeUnspecified AbiType = "ABI_TYPE_UNSPECIFIED"
	// AbiTypeImplementation marks an ABI that decodes calldata directly.
	AbiTypeImplementation AbiType = "ABI_TYPE_IMPLEMENTATION"
	// AbiTypeProxy marks a proxy contract whose calldata is decoded with the ABI
	// at ImplementationAddress.
	AbiTypeProxy AbiType = "ABI_TYPE_PROXY"
)

// ABIValue holds a JSON-encoded ABI definition and optional metadata.
type ABIValue struct {
	Value     string        `json:"value"`
	Signature *ABISignature `json:"signature,omitempty"`
	// AbiType classifies the ABI (implementation vs proxy). nil means the field is
	// omitted (proto None); the parser treats an absent type as implementation.
	AbiType *AbiType `json:"abiType,omitempty"`
	// ImplementationAddress is, for proxies, the 0x-prefixed address whose ABI
	// decodes the calldata. nil means the field is omitted (proto None).
	ImplementationAddress *string `json:"implementationAddress,omitempty"`
}

// EthereumChainMetadata carries optional ABI mappings for Ethereum parse requests.
// ABIMappings maps 0x-prefixed contract address to its ABI JSON.
type EthereumChainMetadata struct {
	NetworkID   *string             `json:"networkId,omitempty"`
	ABIMappings map[string]ABIValue `json:"abiMappings,omitempty"`
}

// RequestChainMetadata is the chain_metadata field in the Turnkey parse request.
type RequestChainMetadata struct {
	Ethereum *EthereumChainMetadata `json:"ethereum,omitempty"`
}

// TurnkeyStamp represents the stamp structure for API key authentication
type TurnkeyStamp struct {
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
	Scheme    string `json:"scheme"`
}

// TurnkeyVisualSignRequest represents the request to Turnkey's visualsign API
type TurnkeyVisualSignRequest struct {
	Request struct {
		UnsignedPayload string                `json:"unsigned_payload"`
		Chain           string                `json:"chain"`
		ChainMetadata   *RequestChainMetadata `json:"chain_metadata,omitempty"`
		// IncludeIntermediateOutput opts into the parser's machine-readable,
		// Borsh-encoded intermediate_output blob. Omitted (false) preserves the
		// legacy response shape and the pre-feature signed digest.
		IncludeIntermediateOutput bool `json:"include_intermediate_output,omitempty"`
	} `json:"request"`
	OrganizationID string `json:"organization_id"`
}

// TurnkeyVisualSignResponse represents the response from Turnkey's visualsign API
type TurnkeyVisualSignResponse struct {
	BootProof *TurnkeyBootProof `json:"bootProof,omitempty"`
	Response  struct {
		ParsedTransaction struct {
			Payload struct {
				SignablePayload    string `json:"signablePayload"`
				ParsedPayload      string `json:"parsedPayload,omitempty"`      // v2
				InputPayloadDigest string `json:"inputPayloadDigest,omitempty"` // v2
				MetadataDigest     string `json:"metadataDigest,omitempty"`     // v2
				// IntermediateOutput is base64-encoded Borsh bytes (proto bytes
				// JSON convention). Omitted by the backend unless requested.
				IntermediateOutput string `json:"intermediateOutput,omitempty"` // v2
			} `json:"payload"`
			Signature *TurnkeySignature `json:"signature,omitempty"`
		} `json:"parsedTransaction"`
	} `json:"response"`
	Error string `json:"error,omitempty"`
}

// TurnkeyBootProof represents the boot proof object in the response.
// Fields match the Turnkey visualsign API bootProof response object.
// See: https://docs.turnkey.com/concepts/enclave-secure-channels
type TurnkeyBootProof struct {
	AwsAttestationDocB64   string `json:"awsAttestationDocB64"`
	QosManifestB64         string `json:"qosManifestB64"`
	QosManifestEnvelopeB64 string `json:"qosManifestEnvelopeB64"`
	EphemeralPublicKeyHex  string `json:"ephemeralPublicKeyHex"`
	EnclaveApp             string `json:"enclaveApp"`
	DeploymentLabel        string `json:"deploymentLabel"`
}

// TurnkeySignature represents the signature object in the response
type TurnkeySignature struct {
	Message   string `json:"message"`
	PublicKey string `json:"publicKey"`
	Scheme    string `json:"scheme"`
	Signature string `json:"signature"`
}

// AttestationQueryRequest represents the request to get attestation document
type AttestationQueryRequest struct {
	OrganizationID string `json:"organizationId"`
	EnclaveType    string `json:"enclaveType"`
	PublicKey      string `json:"publicKey"`
}

// AttestationQueryResponse represents the response from the attestation query
type AttestationQueryResponse struct {
	AttestationDocument string `json:"attestationDocument"`
}

// AttestationType represents different types of attestations
type AttestationType string

const (
	BootAttestationKey AttestationType = "boot_attestation"
	AppAttestationKey  AttestationType = "app_attestation"
)

// SignablePayloadResponse represents the response from CreateSignablePayload
type SignablePayloadResponse struct {
	SignablePayload                  string                     `json:"signablePayload"`
	ParsedPayload                    string                     `json:"parsedPayload,omitempty"`      // v2
	InputPayloadDigest               string                     `json:"inputPayloadDigest,omitempty"` // v2
	MetadataDigest                   string                     `json:"metadataDigest,omitempty"`     // v2
	IntermediateOutputB64            string                     `json:"intermediateOutput,omitempty"` // v2, base64 Borsh
	TurnkeySerializedSignablePayload string                     `json:"turnkeySerializedSignablePayload"`
	ManifestVersion                  manifest.ManifestVersion   `json:"manifestVersion"`
	Attestations                     map[AttestationType]string `json:"attestations"`
	QosManifestB64                   string                     `json:"qosManifestB64,omitempty"`
	QosManifestEnvelopeB64           string                     `json:"qosManifestEnvelopeB64,omitempty"`
	EphemeralPublicKeyHex            string                     `json:"ephemeralPublicKeyHex,omitempty"`
	EnclaveApp                       string                     `json:"enclaveApp,omitempty"`
	DeploymentLabel                  string                     `json:"deploymentLabel,omitempty"`
	// RawAttestation holds the raw JSON bytes of the sibling attestation field
	// (named by Client.AttestationField, default "bootProof") from the parser
	// response envelope. It is nil when that field is absent. This exposes the
	// attestation object to verifier-agnostic consumers without requiring
	// Turnkey/Nitro-specific struct decoding.
	RawAttestation json.RawMessage `json:"rawAttestation,omitempty"`
}

// ECDSASignature represents an ECDSA signature for ASN.1 encoding
type ECDSASignature struct {
	R, S *big.Int
}
