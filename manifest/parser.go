package manifest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/near/borsh-go"
)

// reserializeManifest re-encodes a Manifest struct to get its raw bytes
// using the specified version layout, so that the hash matches the original wire format.
func reserializeManifest(m Manifest, version ManifestVersion) ([]byte, error) {
	switch version {
	case V1:
		// Serialize using V1 layout to preserve hash compatibility
		v1 := ManifestV1{
			Namespace:   m.Namespace,
			Pivot:       PivotConfigV1{Hash: m.Pivot.Hash, Restart: m.Pivot.Restart, Args: m.Pivot.Args},
			ManifestSet: m.ManifestSet,
			ShareSet:    m.ShareSet,
			Enclave:     m.Enclave,
			PatchSet:    m.PatchSet,
		}
		manifestBytes, err := borsh.Serialize(v1)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize v1 manifest: %w", err)
		}
		return manifestBytes, nil
	case V2:
		manifestBytes, err := borsh.Serialize(m)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize v2 manifest: %w", err)
		}
		return manifestBytes, nil
	default:
		return nil, fmt.Errorf("unknown manifest version: %d", version)
	}
}

// decodeRawManifest deserializes raw manifest bytes using the specified version.
func decodeRawManifest(data []byte, version ManifestVersion) (*Manifest, error) {
	switch version {
	case V2:
		var m Manifest
		if err := borsh.Deserialize(&m, data); err != nil {
			return nil, fmt.Errorf("failed to deserialize v2 raw manifest: %w", err)
		}
		return &m, nil
	case V1:
		var v1 ManifestV1
		if err := borsh.Deserialize(&v1, data); err != nil {
			return nil, fmt.Errorf("failed to deserialize v1 (legacy) raw manifest: %w", err)
		}
		m := v1.ToManifest()
		return &m, nil
	default:
		return nil, fmt.Errorf("unknown manifest version: %d", version)
	}
}

// decodeEnvelope deserializes a manifest envelope using the specified version.
func decodeEnvelope(data []byte, version ManifestVersion) (*ManifestEnvelope, error) {
	switch version {
	case V2:
		var env ManifestEnvelope
		if err := borsh.Deserialize(&env, data); err != nil {
			return nil, fmt.Errorf("failed to deserialize v2 manifest envelope: %w", err)
		}
		return &env, nil
	case V1:
		var v1 ManifestEnvelopeV1
		if err := borsh.Deserialize(&v1, data); err != nil {
			return nil, fmt.Errorf("failed to deserialize v1 (legacy) manifest envelope: %w", err)
		}
		env := v1.ToManifestEnvelope()
		return &env, nil
	default:
		return nil, fmt.Errorf("unknown manifest version: %d", version)
	}
}

// DecodeRawManifestFromBase64 decodes a raw manifest (not envelope) from base64.
func DecodeRawManifestFromBase64(manifestB64 string, version ManifestVersion) (*Manifest, []byte, error) {
	manifestBytes, err := base64.StdEncoding.DecodeString(manifestB64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	m, err := decodeRawManifest(manifestBytes, version)
	if err != nil {
		return nil, nil, err
	}
	return m, manifestBytes, nil
}

// DecodeRawManifestFromFile decodes a raw manifest (not envelope) from a binary file.
func DecodeRawManifestFromFile(filePath string, version ManifestVersion) (*Manifest, []byte, error) {
	manifestBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file: %w", err)
	}

	m, err := decodeRawManifest(manifestBytes, version)
	if err != nil {
		return nil, nil, err
	}
	return m, manifestBytes, nil
}

// EnvelopeFormat identifies which decoder a manifest envelope's bytes select.
type EnvelopeFormat int

const (
	// EnvelopeFormatBorsh is QoS's older Borsh-encoded envelope.
	EnvelopeFormatBorsh EnvelopeFormat = iota
	// EnvelopeFormatJSON is QoS's JSON (v2) envelope.
	EnvelopeFormatJSON
)

// DetectEnvelopeFormat sniffs data to select a decoder: a JSON manifest
// envelope begins with '{' (after tolerating leading whitespace) and is
// valid JSON in full. A Borsh envelope's leading bytes are a little-endian
// u32 length prefix, which can
// coincidentally equal '{' (0x7B) for some namespace-name lengths, so a
// single leading byte is not enough to distinguish the formats; the rest of
// the bytes must also parse as valid JSON. This is a parser-selection
// discriminator only, not a trust boundary: each decoder still fails closed
// independently, with no fallback to the other format on a decode failure.
//
// A buffer larger than maxJSONEnvelopeBytes that opens with '{' is routed to
// EnvelopeFormatJSON without running the full json.Valid scan below: that
// scan is O(len(data)), so paying for it before any size limit applies would
// let an oversized '{'-prefixed buffer force a full linear scan on every
// call. DecodeJSONManifestEnvelope enforces the same limit immediately and
// fails closed, so the caller still gets a clear "too large" error rather
// than a confusing Borsh-deserialization failure.
func DetectEnvelopeFormat(data []byte) EnvelopeFormat {
	trimmed := bytes.TrimLeft(data, " \t\n\r")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return EnvelopeFormatBorsh
	}
	if len(trimmed) > maxJSONEnvelopeBytes {
		return EnvelopeFormatJSON
	}
	if json.Valid(trimmed) {
		return EnvelopeFormatJSON
	}
	return EnvelopeFormatBorsh
}

// DecodeManifestEnvelopeFromBase64 decodes a manifest envelope from base64.
// The envelope bytes are sniffed to select a decoder: a JSON (v2) envelope
// is decoded and canonicalized via the QOS JSON path, anything else is
// decoded as Borsh using the given version. There is no fallback between
// formats: a malformed envelope of one format is never retried as the other.
//
// For a JSON envelope, the returned *ManifestEnvelope and *Manifest are a
// lossy projection (see ManifestJSONV2.ToManifest) for reporting purposes
// only; manifestBytes is always the true QOS canonical JSON bytes that
// should be hashed and compared against attestation UserData.
func DecodeManifestEnvelopeFromBase64(manifestB64 string, version ManifestVersion) (*ManifestEnvelope, *Manifest, []byte, []byte, error) {
	envelopeBytes, err := base64.StdEncoding.DecodeString(manifestB64)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	return DecodeManifestEnvelopeFromBytes(envelopeBytes, version)
}

// DecodeManifestEnvelopeFromFile decodes a manifest envelope from a file. See
// DecodeManifestEnvelopeFromBase64 for the format-sniffing behavior.
func DecodeManifestEnvelopeFromFile(filePath string, version ManifestVersion) (*ManifestEnvelope, *Manifest, []byte, []byte, error) {
	envelopeBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to read file: %w", err)
	}
	return DecodeManifestEnvelopeFromBytes(envelopeBytes, version)
}

// DecodeManifestEnvelopeFromBytes decodes a manifest envelope whose raw bytes
// are already in hand (e.g. after a caller has read a file or base64-decoded
// a string for its own purposes, such as sniffing the format up front). See
// DecodeManifestEnvelopeFromBase64 for the format-sniffing behavior.
func DecodeManifestEnvelopeFromBytes(envelopeBytes []byte, version ManifestVersion) (*ManifestEnvelope, *Manifest, []byte, []byte, error) {
	if DetectEnvelopeFormat(envelopeBytes) == EnvelopeFormatJSON {
		jsonEnv, manifestBytes, err := DecodeJSONManifestEnvelope(envelopeBytes)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		projected := jsonEnv.ToManifestEnvelope()
		return &projected, &projected.Manifest, manifestBytes, envelopeBytes, nil
	}

	env, err := decodeEnvelope(envelopeBytes, version)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	manifestBytes, err := reserializeManifest(env.Manifest, version)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return env, &env.Manifest, manifestBytes, envelopeBytes, nil
}

// DecodeManifestFromBase64 decodes a base64-encoded manifest envelope.
func DecodeManifestFromBase64(manifestB64 string, version ManifestVersion) (*Manifest, []byte, []byte, error) {
	envelopeBytes, err := base64.StdEncoding.DecodeString(manifestB64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	env, err := decodeEnvelope(envelopeBytes, version)
	if err != nil {
		return nil, nil, nil, err
	}

	manifestBytes, err := reserializeManifest(env.Manifest, version)
	if err != nil {
		return nil, nil, nil, err
	}
	return &env.Manifest, manifestBytes, envelopeBytes, nil
}

// DecodeManifestFromFile decodes a manifest from a binary file.
// Tries envelope first, then raw manifest, using the specified version.
func DecodeManifestFromFile(filePath string, version ManifestVersion) (*Manifest, []byte, []byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try envelope first
	env, envErr := decodeEnvelope(data, version)
	if envErr == nil {
		manifestBytes, err := reserializeManifest(env.Manifest, version)
		if err != nil {
			return nil, nil, nil, err
		}
		return &env.Manifest, manifestBytes, data, nil
	}

	// Try raw manifest
	m, rawErr := decodeRawManifest(data, version)
	if rawErr == nil {
		return m, data, data, nil
	}

	return nil, nil, nil, fmt.Errorf("failed to deserialize as envelope or raw manifest: %w", errors.Join(envErr, rawErr))
}
