package manifest

import (
	"encoding/base64"
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

// DecodeManifestEnvelopeFromBase64 decodes a manifest envelope from base64.
func DecodeManifestEnvelopeFromBase64(manifestB64 string, version ManifestVersion) (*ManifestEnvelope, *Manifest, []byte, []byte, error) {
	envelopeBytes, err := base64.StdEncoding.DecodeString(manifestB64)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to decode base64: %w", err)
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

// DecodeManifestEnvelopeFromFile decodes a manifest envelope from a binary file.
func DecodeManifestEnvelopeFromFile(filePath string, version ManifestVersion) (*ManifestEnvelope, *Manifest, []byte, []byte, error) {
	envelopeBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to read file: %w", err)
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
