package manifest

import (
	"encoding/base64"
	"fmt"
	"os"
)

// DecodeManifestEnvelopeFromBase64 decodes a QOS JSON (v2) manifest envelope
// from base64.
//
// The returned *ManifestEnvelope and *Manifest are a lossy projection (see
// ManifestJSONV2.ToManifest) for reporting purposes only; manifestBytes is
// always the true QOS canonical JSON bytes that should be hashed and
// compared against attestation UserData.
func DecodeManifestEnvelopeFromBase64(manifestB64 string) (*ManifestEnvelope, *Manifest, []byte, []byte, error) {
	envelopeBytes, err := base64.StdEncoding.DecodeString(manifestB64)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	return DecodeManifestEnvelopeFromBytes(envelopeBytes)
}

// DecodeManifestEnvelopeFromFile decodes a QOS JSON (v2) manifest envelope
// from a file. See DecodeManifestEnvelopeFromBase64 for the return values.
func DecodeManifestEnvelopeFromFile(filePath string) (*ManifestEnvelope, *Manifest, []byte, []byte, error) {
	envelopeBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to read file: %w", err)
	}
	return DecodeManifestEnvelopeFromBytes(envelopeBytes)
}

// DecodeManifestEnvelopeFromBytes decodes a QOS JSON (v2) manifest envelope
// whose raw bytes are already in hand (e.g. after a caller has read a file or
// base64-decoded a string for its own purposes). See
// DecodeManifestEnvelopeFromBase64 for the return values.
func DecodeManifestEnvelopeFromBytes(envelopeBytes []byte) (*ManifestEnvelope, *Manifest, []byte, []byte, error) {
	jsonEnv, manifestBytes, err := DecodeJSONManifestEnvelope(envelopeBytes)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	projected := jsonEnv.ToManifestEnvelope()
	return &projected, &projected.Manifest, manifestBytes, envelopeBytes, nil
}
