package manifest

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/testdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeManifestEnvelopeFromFile(t *testing.T) {
	t.Run("non-existent file", func(t *testing.T) {
		_, _, _, _, err := DecodeManifestEnvelopeFromFile("does-not-exist.bin")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read file")
	})

	t.Run("invalid envelope data", func(t *testing.T) {
		tmpDir := t.TempDir()
		invalidPath := filepath.Join(tmpDir, "invalid.bin")
		err := os.WriteFile(invalidPath, []byte{0xFF, 0xFE}, 0644)
		assert.NoError(t, err)

		_, _, _, _, err = DecodeManifestEnvelopeFromFile(invalidPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid QOS JSON manifest envelope")
	})

	t.Run("valid JSON envelope file", func(t *testing.T) {
		tmpDir := t.TempDir()
		p := filepath.Join(tmpDir, "envelope.json")
		require.NoError(t, os.WriteFile(p, testdata.QosManifestEnvelopeV2JSON, 0644))

		_, m, manifestBytes, envelopeBytes, err := DecodeManifestEnvelopeFromFile(p)
		require.NoError(t, err)
		require.NotNil(t, m)
		assert.Equal(t, "synthetic-turnkey-namespace", m.Namespace.Name)
		assert.Equal(t, testdata.QosManifestEnvelopeV2JSON, envelopeBytes)
		expected := strings.TrimSuffix(string(testdata.QosManifestEnvelopeV2CanonicalJSON), "\n")
		assert.Equal(t, expected, string(manifestBytes))
	})
}

func TestDecodeManifestEnvelopeFromBase64(t *testing.T) {
	t.Run("invalid base64", func(t *testing.T) {
		_, _, _, _, err := DecodeManifestEnvelopeFromBase64("!!!invalid!!!")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode base64")
	})

	t.Run("invalid envelope data", func(t *testing.T) {
		invalidB64 := base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFE})
		_, _, _, _, err := DecodeManifestEnvelopeFromBase64(invalidB64)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid QOS JSON manifest envelope")
	})

	t.Run("empty base64", func(t *testing.T) {
		_, _, _, _, err := DecodeManifestEnvelopeFromBase64("")
		assert.Error(t, err)
	})

	t.Run("valid JSON envelope", func(t *testing.T) {
		b64 := base64.StdEncoding.EncodeToString(testdata.QosManifestEnvelopeV2JSON)

		env, m, manifestBytes, returnedEnvBytes, err := DecodeManifestEnvelopeFromBase64(b64)
		require.NoError(t, err)
		require.NotNil(t, env)
		require.NotNil(t, m)
		assert.Equal(t, "synthetic-turnkey-namespace", m.Namespace.Name)
		assert.Equal(t, uint32(7), m.Namespace.Nonce)
		assert.Equal(t, RestartPolicyAlways, m.Pivot.Restart)
		assert.Empty(t, m.PatchSet.Members, "JSON manifests have no patch set")
		assert.Equal(t, testdata.QosManifestEnvelopeV2JSON, returnedEnvBytes)
		expected := strings.TrimSuffix(string(testdata.QosManifestEnvelopeV2CanonicalJSON), "\n")
		assert.Equal(t, expected, string(manifestBytes))
	})
}

func TestDecodeManifestEnvelopeFromBase64_NoFallback(t *testing.T) {
	// `{}` is valid JSON but fails the strict JSON manifest-envelope schema
	// (missing required fields); that failure must be returned as-is.
	_, _, _, _, err := DecodeManifestEnvelopeFromBase64(base64.StdEncoding.EncodeToString([]byte(`{}`)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required field")

	_, _, _, _, err = DecodeManifestEnvelopeFromBase64(base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF, 0xFF}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid QOS JSON manifest envelope")
}
