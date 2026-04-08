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
	"math/big"
)

// TurnkeyAPIKey represents the API key configuration
type TurnkeyAPIKey struct {
	PublicKey      string
	PrivateKey     *ecdsa.PrivateKey
	OrganizationID string
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
		UnsignedPayload string `json:"unsigned_payload"`
		Chain           string `json:"chain"`
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
	TurnkeySerializedSignablePayload string                     `json:"turnkeySerializedSignablePayload"`
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
