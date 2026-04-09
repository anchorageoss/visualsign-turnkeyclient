package manifest

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/testdata"
	"github.com/near/borsh-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReserializeManifest(t *testing.T) {
	t.Run("valid manifest", func(t *testing.T) {
		m := Manifest{
			Namespace: Namespace{
				Name:  "test",
				Nonce: 1,
			},
			Pivot: PivotConfig{
				Restart: RestartPolicyNever,
			},
		}

		bytes, err := reserializeManifest(m)
		require.NoError(t, err)
		require.NotEmpty(t, bytes)

		// Verify it can be deserialized back
		var m2 Manifest
		err = borsh.Deserialize(&m2, bytes)
		require.NoError(t, err)
		require.Equal(t, m.Namespace.Name, m2.Namespace.Name)
		require.Equal(t, m.Namespace.Nonce, m2.Namespace.Nonce)
	})

	t.Run("deterministic serialization", func(t *testing.T) {
		m := Manifest{
			Namespace: Namespace{
				Name:  "deterministic",
				Nonce: 42,
			},
		}

		bytes1, err := reserializeManifest(m)
		require.NoError(t, err)

		bytes2, err := reserializeManifest(m)
		require.NoError(t, err)

		require.Equal(t, bytes1, bytes2, "Serialization should be deterministic")
	})
}

func TestDecodeManifestFromBase64(t *testing.T) {
	t.Run("invalid base64", func(t *testing.T) {
		_, _, _, err := DecodeManifestFromBase64("not-valid-base64!", V2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode base64")
	})

	t.Run("empty base64", func(t *testing.T) {
		_, _, _, err := DecodeManifestFromBase64("", V2)
		assert.Error(t, err)
	})

	t.Run("invalid borsh data", func(t *testing.T) {
		invalidB64 := base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF})
		_, _, _, err := DecodeManifestFromBase64(invalidB64, V2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to deserialize v2 manifest envelope")
	})
}

func TestDecodeManifestFromFile(t *testing.T) {
	testdataDir := "../testdata"

	t.Run("valid manifest.bin", func(t *testing.T) {
		manifestPath := filepath.Join(testdataDir, "manifest.bin")
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			t.Skip("testdata/manifest.bin not found")
		}

		manifest, manifestBytes, envelopeBytes, err := DecodeManifestFromFile(manifestPath, V2)
		assert.NoError(t, err)
		assert.NotNil(t, manifest)
		assert.NotEmpty(t, manifestBytes)
		assert.NotEmpty(t, envelopeBytes)
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, _, _, err := DecodeManifestFromFile("does-not-exist.bin", V2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read file")
	})
}

func TestDecodeRawManifestFromFile(t *testing.T) {
	t.Run("non-existent file", func(t *testing.T) {
		_, _, err := DecodeRawManifestFromFile("does-not-exist.bin", V2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read file")
	})

	t.Run("invalid manifest data", func(t *testing.T) {
		tmpDir := t.TempDir()
		invalidPath := filepath.Join(tmpDir, "invalid.bin")
		err := os.WriteFile(invalidPath, []byte{0xFF}, 0644)
		assert.NoError(t, err)

		_, _, err = DecodeRawManifestFromFile(invalidPath, V2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to deserialize v2 raw manifest")
	})
}

func TestDecodeRawManifestFromBase64(t *testing.T) {
	t.Run("invalid base64", func(t *testing.T) {
		_, _, err := DecodeRawManifestFromBase64("!@#$%", V2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode base64")
	})

	t.Run("invalid borsh", func(t *testing.T) {
		invalidB64 := base64.StdEncoding.EncodeToString([]byte{0xFF})
		_, _, err := DecodeRawManifestFromBase64(invalidB64, V2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to deserialize v2 raw manifest")
	})

	t.Run("empty base64", func(t *testing.T) {
		_, _, err := DecodeRawManifestFromBase64("", V2)
		assert.Error(t, err)
	})
}

func TestDecodeManifestEnvelopeFromFile(t *testing.T) {
	t.Run("non-existent file", func(t *testing.T) {
		_, _, _, _, err := DecodeManifestEnvelopeFromFile("does-not-exist.bin", V2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read file")
	})

	t.Run("invalid envelope data", func(t *testing.T) {
		tmpDir := t.TempDir()
		invalidPath := filepath.Join(tmpDir, "invalid.bin")
		err := os.WriteFile(invalidPath, []byte{0xFF, 0xFE}, 0644)
		assert.NoError(t, err)

		_, _, _, _, err = DecodeManifestEnvelopeFromFile(invalidPath, V2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to deserialize v2 manifest envelope")
	})
}

func TestDecodeManifestEnvelopeFromBase64(t *testing.T) {
	t.Run("invalid base64", func(t *testing.T) {
		_, _, _, _, err := DecodeManifestEnvelopeFromBase64("!!!invalid!!!", V2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode base64")
	})

	t.Run("invalid envelope data", func(t *testing.T) {
		invalidB64 := base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFE})
		_, _, _, _, err := DecodeManifestEnvelopeFromBase64(invalidB64, V2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to deserialize v2 manifest envelope")
	})

	t.Run("empty base64", func(t *testing.T) {
		_, _, _, _, err := DecodeManifestEnvelopeFromBase64("", V2)
		assert.Error(t, err)
	})
}

// Test with actual embedded testdata (v2 manifest)
func TestDecodeActualManifest(t *testing.T) {
	manifestBytes := testdata.ManifestBin
	manifestB64 := base64.StdEncoding.EncodeToString(manifestBytes)

	manifest, decodedBytes, err := DecodeRawManifestFromBase64(manifestB64, V2)
	assert.NoError(t, err)
	assert.NotNil(t, manifest)
	assert.NotEmpty(t, decodedBytes)

	hash := ComputeHash(manifestBytes)
	assert.Len(t, hash, 64)

	reserializedHash := ComputeHash(decodedBytes)
	assert.Equal(t, hash, reserializedHash, "reserialized manifest should have same hash")
}

// TestDecodeManifestSuccess tests the happy path with synthetic data
func TestDecodeManifestSuccess(t *testing.T) {
	t.Run("decode and reserialize manifest envelope", func(t *testing.T) {
		manifest := Manifest{
			Namespace: Namespace{
				Name:  "test-namespace",
				Nonce: 123,
			},
			Pivot: PivotConfig{
				Restart: RestartPolicyAlways,
				Args:    []string{"arg1", "arg2"},
			},
			ManifestSet: ManifestSet{Threshold: 2},
			ShareSet:    ShareSet{Threshold: 3},
			Enclave:     NitroConfig{QosCommit: "abc123"},
			PatchSet:    PatchSet{Threshold: 1},
		}

		envelope := ManifestEnvelope{
			Manifest:             manifest,
			ManifestSetApprovals: []Approval{},
			ShareSetApprovals:    []Approval{},
		}

		envelopeBytes, err := borsh.Serialize(envelope)
		require.NoError(t, err)

		envelopeB64 := base64.StdEncoding.EncodeToString(envelopeBytes)

		decodedManifest, manifestBytes, returnedEnvelopeBytes, err := DecodeManifestFromBase64(envelopeB64, V2)
		require.NoError(t, err)
		require.NotNil(t, decodedManifest)
		require.NotEmpty(t, manifestBytes)
		require.Equal(t, envelopeBytes, returnedEnvelopeBytes)

		require.Equal(t, "test-namespace", decodedManifest.Namespace.Name)
		require.Equal(t, uint32(123), decodedManifest.Namespace.Nonce)
		require.Equal(t, RestartPolicyAlways, decodedManifest.Pivot.Restart)
	})

	t.Run("decode raw manifest from base64", func(t *testing.T) {
		manifest := Manifest{
			Namespace: Namespace{Name: "raw-test", Nonce: 456},
			Pivot:     PivotConfig{Restart: RestartPolicyNever},
		}

		manifestBytes, err := borsh.Serialize(manifest)
		require.NoError(t, err)

		manifestB64 := base64.StdEncoding.EncodeToString(manifestBytes)

		decoded, decodedBytes, err := DecodeRawManifestFromBase64(manifestB64, V2)
		require.NoError(t, err)
		require.NotNil(t, decoded)
		require.Equal(t, manifestBytes, decodedBytes)
		require.Equal(t, "raw-test", decoded.Namespace.Name)
		require.Equal(t, uint32(456), decoded.Namespace.Nonce)
	})

	t.Run("decode envelope from base64", func(t *testing.T) {
		manifest := Manifest{
			Namespace: Namespace{Name: "envelope-test", Nonce: 789},
		}
		envelope := ManifestEnvelope{Manifest: manifest}

		envelopeBytes, err := borsh.Serialize(envelope)
		require.NoError(t, err)

		envelopeB64 := base64.StdEncoding.EncodeToString(envelopeBytes)

		decodedEnv, decodedManifest, manifestBytes, returnedEnvBytes, err := DecodeManifestEnvelopeFromBase64(envelopeB64, V2)
		require.NoError(t, err)
		require.NotNil(t, decodedEnv)
		require.NotNil(t, decodedManifest)
		require.NotEmpty(t, manifestBytes)
		require.Equal(t, envelopeBytes, returnedEnvBytes)
		require.Equal(t, "envelope-test", decodedManifest.Namespace.Name)
	})
}
