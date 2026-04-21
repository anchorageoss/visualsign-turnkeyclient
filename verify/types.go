// Package verify provides end-to-end verification of transactions executed in AWS Nitro enclaves.
//
// The verification process validates:
//   - AWS Nitro attestation document authenticity
//   - ECDSA signature correctness
//   - QoS manifest integrity via hash comparison
//   - PCR (Platform Configuration Register) values
//
// # Verification Flow
//
// Call Verify with an attestation document and transaction details:
//
//	result, err := verifyService.Verify(ctx, &verify.VerifyRequest{
//		UnsignedPayload: "base64-payload",
//		QosManifestHex:  "expected-manifest-hash",
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	if !result.Valid {
//		log.Printf("Verification failed: %s", result.Message)
//	}
//
// # Detailed Results
//
// VerifyResult includes detailed information about each step:
//   - Attestation verification status and PCR values
//   - Signature verification with public key extraction
//   - Manifest decoding and hash comparison
//   - Comprehensive error messages explaining failures
//
// # Customization
//
// Use VerifyRequest fields to customize verification:
//   - QosManifestHex: Compare manifest hash (optional)
//   - PivotBinaryHashHex: Verify binary hash (optional)
//   - SaveManifestPath: Save manifest to file (optional)
package verify

import (
	"crypto/ecdsa"

	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
)

// VerifyRequest represents the parameters for verification
type VerifyRequest struct {
	UnsignedPayload    string
	QosManifestHex     string
	PivotBinaryHashHex string
	SaveManifestPath   string
	Chain              string
}

// VerifyResult represents the result of verification
type VerifyResult struct {
	Valid                   bool                        `json:"valid"`
	AttestationValid        bool                        `json:"attestationValid"`
	SignatureValid          bool                        `json:"signatureValid"`
	ModuleID                string                      `json:"moduleId"`
	PublicKeyHex            string                      `json:"publicKey"`
	SignablePayload         string                      `json:"signablePayload"`
	InputPayloadDigest      string                      `json:"inputPayloadDigest,omitempty"`
	MetadataDigest          string                      `json:"metadataDigest,omitempty"`
	MessageHex              string                      `json:"message"`
	SignatureHex            string                      `json:"signature"`
	QosManifestHash         string                      `json:"qosManifest,omitempty"`
	PivotBinaryHash         string                      `json:"pivotBinaryHash,omitempty"`
	PCR4                    string                      `json:"pcr4,omitempty"`
	UserData                []byte                      `json:"-"`
	PCRs                    map[uint][]byte             `json:"-"`
	PCRValidationResults    []PCRValidationResult       `json:"-"`
	PublicKey               *ecdsa.PublicKey            `json:"-"`
	Manifest                *manifest.Manifest          `json:"-"`
	AttestationDocument     interface{}                 `json:"-"`
	ManifestReserialization ManifestSerializationResult `json:"-"`
}

// PCRValidationResult represents the result of validating a single PCR
type PCRValidationResult struct {
	Index    uint   `json:"index"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Valid    bool   `json:"valid"`
}

// ManifestSerializationResult tracks manifest hash verification
type ManifestSerializationResult struct {
	RawManifestHash          string
	ReserializedManifestHash string
	EnvelopeHash             string
	UserDataHash             string
	RawManifestB64           string // Base64-encoded manifest for debugging
	EnvelopeB64              string // Base64-encoded envelope for debugging
	Matches                  bool
	ReserializationNeeded    bool
	Error                    string
}

// ParseResult represents the result of parsing transaction
type ParseResult struct {
	SignablePayload                  string            `json:"signablePayload"`
	TurnkeySerializedSignablePayload string            `json:"turnkeySerializedSignablePayload"`
	Attestations                     map[string]string `json:"attestations"`
	QosManifestB64                   string            `json:"qosManifestB64,omitempty"`
	QosManifestEnvelopeB64           string            `json:"qosManifestEnvelopeB64,omitempty"`
}
