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
	"fmt"
	"math/big"
	"strings"

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

// SignatureMetadata is the parser proto's own name for the shape ABISignature
// mirrors: a signature value plus key-value metadata naming its algorithm and
// public key. An alias rather than a second type, because the proto reuses one
// message for ABIs, IDLs and token metadata alike, and so should this.
type SignatureMetadata = ABISignature

// TokenOriginChain selects which curator identity and curve a
// TokenMetadataEntry signature is checked against. It is dispatched by the
// origin chain of the underlying bridged asset rather than by NEAR: an
// Ethereum-origin asset verifies with secp256k1, a Solana-origin one with
// ed25519, and a NEAR-native one with ed25519 under a distinct identity.
type TokenOriginChain string

const (
	// TokenOriginChainUnspecified is the proto default. The parser treats it as Near.
	TokenOriginChainUnspecified TokenOriginChain = "TOKEN_ORIGIN_CHAIN_UNSPECIFIED"
	TokenOriginChainNear        TokenOriginChain = "TOKEN_ORIGIN_CHAIN_NEAR"
	TokenOriginChainEthereum    TokenOriginChain = "TOKEN_ORIGIN_CHAIN_ETHEREUM"
	TokenOriginChainSolana      TokenOriginChain = "TOKEN_ORIGIN_CHAIN_SOLANA"
)

// TokenMetadataEntry supplies the symbol and decimals for one NEAR Intents
// asset, so an amount renders as "1 wNEAR" rather than as base units against a
// bare asset id.
//
// Value is signed verbatim as supplied, mirroring ABIValue.Value: the signature
// covers exactly these bytes, not a re-derived encoding. An entry the parser
// cannot attribute to an enrolled signer renders with a caveat rather than
// being trusted silently.
type TokenMetadataEntry struct {
	Value     string             `json:"value"`
	Signature *SignatureMetadata `json:"signature,omitempty"`
	// OriginChain is nil when the field is omitted (proto None); the parser
	// treats an absent origin as Near.
	OriginChain *TokenOriginChain `json:"originChain,omitempty"`
}

// NearChainMetadata carries optional per-request data for NEAR parse requests.
// TokenMappings is keyed by NEAR Intents asset id (e.g. "nep141:wrap.near"),
// letting a caller supply metadata for assets the parser's compiled-in seed
// table does not cover.
type NearChainMetadata struct {
	NetworkID     *string                       `json:"networkId,omitempty"`
	TokenMappings map[string]TokenMetadataEntry `json:"tokenMappings,omitempty"`
}

// EthereumChainMetadata carries optional ABI mappings for Ethereum parse requests.
// ABIMappings maps 0x-prefixed contract address to its ABI JSON.
type EthereumChainMetadata struct {
	NetworkID   *string             `json:"networkId,omitempty"`
	ABIMappings map[string]ABIValue `json:"abiMappings,omitempty"`
}

// SolanaChainMetadata carries optional simulation-derived data for Solana
// parse requests, letting the parser flag registered/unregistered status for
// instructions that only exist at execution time and are never present in
// the raw unsigned transaction the parser otherwise decodes.
type SolanaChainMetadata struct {
	// SimulatedTransactionResult is the raw simulateTransaction RPC response
	// bytes (innerInstructions section), sent as-is with no backend-side
	// decode/reshape. The parser runs this through the same static-decode
	// path (parse_transaction_with_idls) it already uses for
	// unsigned_payload.
	SimulatedTransactionResult []byte `json:"simulatedTransactionResult,omitempty"`
}

// RequestChainMetadata is the chain_metadata field in the Turnkey parse request.
//
// The wire shape is internally tagged, not the {"ethereum":{...}} /
// {"solana":{...}} shape this struct's field names might suggest: the parser
// gateway's generated ChainMetadata is an untagged oneof, which is ambiguous
// (e.g. a Solana payload with only networkId decodes as Ethereum), so the
// gateway requires an explicit "chain" discriminator alongside the variant's
// fields flattened into the same object. See MarshalJSON.
type RequestChainMetadata struct {
	Ethereum *EthereumChainMetadata `json:"-"`
	Solana   *SolanaChainMetadata   `json:"-"`
	Near     *NearChainMetadata     `json:"-"`
}

// setVariants names the variants that are set, in declaration order. Exactly
// one must be, and reporting which were found makes a caller's mistake legible
// in the error rather than only saying the count was wrong.
func (m RequestChainMetadata) setVariants() []string {
	var set []string
	if m.Ethereum != nil {
		set = append(set, "Ethereum")
	}
	if m.Solana != nil {
		set = append(set, "Solana")
	}
	if m.Near != nil {
		set = append(set, "Near")
	}
	return set
}

// MarshalJSON flattens RequestChainMetadata into the gateway's internally-tagged
// shape: {"chain": "CHAIN_SOLANA", ...SolanaChainMetadata fields...}. Exactly
// one variant must be set.
func (m RequestChainMetadata) MarshalJSON() ([]byte, error) {
	if set := m.setVariants(); len(set) != 1 {
		return nil, fmt.Errorf(
			"RequestChainMetadata: exactly one variant must be set, got %d %v", len(set), set)
	}
	switch {
	case m.Solana != nil:
		return marshalTaggedChainMetadata("CHAIN_SOLANA", m.Solana)
	case m.Ethereum != nil:
		return marshalTaggedChainMetadata("CHAIN_ETHEREUM", m.Ethereum)
	case m.Near != nil:
		return marshalTaggedChainMetadata("CHAIN_NEAR", m.Near)
	default:
		// Unreachable while setVariants above reports exactly one, and named
		// rather than folded into the NEAR arm so a variant added to the struct
		// without a case here errors instead of marshalling as NEAR with a nil
		// payload -- which marshalTaggedChainMetadata would turn into a panic
		// on a nil map.
		return nil, fmt.Errorf(
			"RequestChainMetadata: exactly one variant is set but none matched; a variant was added without a MarshalJSON case")
	}
}

// UnmarshalJSON parses the gateway's internally-tagged shape produced by
// MarshalJSON: {"chain": "CHAIN_SOLANA", ...fields...}. This is the only wire
// shape the gateway's ChainMetadataInput has ever accepted (including for
// Ethereum, from the day chain_metadata support was added), so there is no
// legacy untagged shape to also support.
func (m *RequestChainMetadata) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("failed to decode chain metadata: %w", err)
	}

	rawChain, ok := fields["chain"]
	if !ok {
		return fmt.Errorf(`RequestChainMetadata: missing "chain" discriminator`)
	}
	var chain string
	if err := json.Unmarshal(rawChain, &chain); err != nil {
		return fmt.Errorf("failed to decode chain discriminator: %w", err)
	}
	delete(fields, "chain")
	remaining, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("failed to re-encode chain metadata fields: %w", err)
	}

	// Every variant is cleared first, so decoding into a reused value cannot
	// leave a stale variant set alongside the one just read.
	*m = RequestChainMetadata{}
	switch {
	case strings.HasPrefix(chain, "CHAIN_ETHEREUM"):
		var eth EthereumChainMetadata
		if err := json.Unmarshal(remaining, &eth); err != nil {
			return fmt.Errorf("failed to decode ethereum chain metadata: %w", err)
		}
		m.Ethereum = &eth
	case strings.HasPrefix(chain, "CHAIN_SOLANA"):
		var sol SolanaChainMetadata
		if err := json.Unmarshal(remaining, &sol); err != nil {
			return fmt.Errorf("failed to decode solana chain metadata: %w", err)
		}
		m.Solana = &sol
	case strings.HasPrefix(chain, "CHAIN_NEAR"):
		var near NearChainMetadata
		if err := json.Unmarshal(remaining, &near); err != nil {
			return fmt.Errorf("failed to decode near chain metadata: %w", err)
		}
		m.Near = &near
	default:
		return fmt.Errorf("RequestChainMetadata: unsupported chain discriminator %q", chain)
	}
	return nil
}

// marshalTaggedChainMetadata marshals metadata to JSON and splices in a "chain"
// key alongside its fields, matching the gateway's serde(tag = "chain") shape.
func marshalTaggedChainMetadata(chain string, metadata any) ([]byte, error) {
	fields, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal chain metadata: %w", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(fields, &m); err != nil {
		return nil, fmt.Errorf("failed to decode chain metadata fields: %w", err)
	}
	chainJSON, err := json.Marshal(chain)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal chain discriminator: %w", err)
	}
	m["chain"] = chainJSON
	return json.Marshal(m)
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
}

// ECDSASignature represents an ECDSA signature for ASN.1 encoding
type ECDSASignature struct {
	R, S *big.Int
}
