package manifest

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/near/borsh-go"
)

// reserializeManifest re-encodes a Manifest struct to get its raw bytes
// This is used to compute hashes consistently across envelope and raw manifest formats
func reserializeManifest(m Manifest) ([]byte, error) {
	manifestBytes, err := borsh.Serialize(m)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize manifest: %w", err)
	}
	return manifestBytes, nil
}

// DecodeManifestFromBase64 decodes a base64-encoded manifest envelope and returns the manifest and envelope bytes.
// Tries v2 format first, falls back to v0 (legacy) format.
func DecodeManifestFromBase64(manifestB64 string) (*Manifest, []byte, []byte, error) {
	// Decode base64
	envelopeBytes, err := base64.StdEncoding.DecodeString(manifestB64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Try v2 envelope first
	var env ManifestEnvelope
	if err := borsh.Deserialize(&env, envelopeBytes); err == nil {
		manifestBytes, err := reserializeManifest(env.Manifest)
		if err != nil {
			return nil, nil, nil, err
		}
		return &env.Manifest, manifestBytes, envelopeBytes, nil
	}

	// Fall back to v0 envelope
	var envV0 ManifestEnvelopeV0
	if err := borsh.Deserialize(&envV0, envelopeBytes); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to deserialize manifest envelope (tried v2 and v0): %w", err)
	}
	converted := envV0.ToManifestEnvelope()
	manifestBytes, err := reserializeManifest(converted.Manifest)
	if err != nil {
		return nil, nil, nil, err
	}
	return &converted.Manifest, manifestBytes, envelopeBytes, nil
}

// DecodeManifestFromFile decodes a manifest envelope from a binary file.
// Tries v2 formats first, falls back to v0 (legacy) formats.
func DecodeManifestFromFile(filePath string) (*Manifest, []byte, []byte, error) {
	envelopeBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try v2 envelope
	var env ManifestEnvelope
	if err := borsh.Deserialize(&env, envelopeBytes); err == nil {
		manifestBytes, err := reserializeManifest(env.Manifest)
		if err != nil {
			return nil, nil, nil, err
		}
		return &env.Manifest, manifestBytes, envelopeBytes, nil
	}

	// Try v0 envelope
	var envV0 ManifestEnvelopeV0
	if err := borsh.Deserialize(&envV0, envelopeBytes); err == nil {
		converted := envV0.ToManifestEnvelope()
		manifestBytes, err := reserializeManifest(converted.Manifest)
		if err != nil {
			return nil, nil, nil, err
		}
		return &converted.Manifest, manifestBytes, envelopeBytes, nil
	}

	// Try v2 raw manifest
	var manifest Manifest
	if err := borsh.Deserialize(&manifest, envelopeBytes); err == nil {
		return &manifest, envelopeBytes, envelopeBytes, nil
	}

	// Try v0 raw manifest
	var v0 ManifestV0
	if err := borsh.Deserialize(&v0, envelopeBytes); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to deserialize as envelope or manifest (tried v2 and v0): %w", err)
	}
	m := v0.ToManifest()
	return &m, envelopeBytes, envelopeBytes, nil
}

// DecodeRawManifestFromFile decodes a raw manifest (not envelope) from a binary file.
// Tries v2 format first, falls back to v0 (legacy) format.
func DecodeRawManifestFromFile(filePath string) (*Manifest, []byte, error) {
	manifestBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file: %w", err)
	}

	var manifest Manifest
	if err := borsh.Deserialize(&manifest, manifestBytes); err == nil {
		return &manifest, manifestBytes, nil
	}

	var v0 ManifestV0
	if err := borsh.Deserialize(&v0, manifestBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to deserialize raw manifest (tried v2 and v0): %w", err)
	}
	m := v0.ToManifest()
	return &m, manifestBytes, nil
}

// DecodeRawManifestFromBase64 decodes a raw manifest (not envelope) from base64.
// Tries v2 format first, falls back to v0 (legacy) format.
func DecodeRawManifestFromBase64(manifestB64 string) (*Manifest, []byte, error) {
	// Decode base64
	manifestBytes, err := base64.StdEncoding.DecodeString(manifestB64)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Try v2 format first
	var manifest Manifest
	if err := borsh.Deserialize(&manifest, manifestBytes); err == nil {
		return &manifest, manifestBytes, nil
	}

	// Fall back to v0 (legacy) format
	var v0 ManifestV0
	if err := borsh.Deserialize(&v0, manifestBytes); err != nil {
		return nil, nil, fmt.Errorf("failed to deserialize raw manifest (tried v2 and v0): %w", err)
	}
	m := v0.ToManifest()
	return &m, manifestBytes, nil
}

// DecodeManifestEnvelopeFromFile decodes a manifest envelope from a binary file.
// Tries v2 format first, falls back to v0 (legacy) format.
func DecodeManifestEnvelopeFromFile(filePath string) (*ManifestEnvelope, *Manifest, []byte, []byte, error) {
	envelopeBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to read file: %w", err)
	}

	var env ManifestEnvelope
	if err := borsh.Deserialize(&env, envelopeBytes); err == nil {
		manifestBytes, err := reserializeManifest(env.Manifest)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return &env, &env.Manifest, manifestBytes, envelopeBytes, nil
	}

	var envV0 ManifestEnvelopeV0
	if err := borsh.Deserialize(&envV0, envelopeBytes); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to deserialize manifest envelope (tried v2 and v0): %w", err)
	}
	converted := envV0.ToManifestEnvelope()
	manifestBytes, err := reserializeManifest(converted.Manifest)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return &converted, &converted.Manifest, manifestBytes, envelopeBytes, nil
}

// DecodeManifestEnvelopeFromBase64 decodes a manifest envelope from base64.
// Tries v2 format first, falls back to v0 (legacy) format.
func DecodeManifestEnvelopeFromBase64(manifestB64 string) (*ManifestEnvelope, *Manifest, []byte, []byte, error) {
	// Decode base64
	envelopeBytes, err := base64.StdEncoding.DecodeString(manifestB64)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Try v2 format first
	var env ManifestEnvelope
	if err := borsh.Deserialize(&env, envelopeBytes); err == nil {
		manifestBytes, err := reserializeManifest(env.Manifest)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return &env, &env.Manifest, manifestBytes, envelopeBytes, nil
	}

	// Fall back to v0 (legacy) format
	var envV0 ManifestEnvelopeV0
	if err := borsh.Deserialize(&envV0, envelopeBytes); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to deserialize manifest envelope (tried v2 and v0): %w", err)
	}
	converted := envV0.ToManifestEnvelope()
	manifestBytes, err := reserializeManifest(converted.Manifest)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return &converted, &converted.Manifest, manifestBytes, envelopeBytes, nil
}
