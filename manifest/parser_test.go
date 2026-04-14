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

		bytes, err := reserializeManifest(m, V2)
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

		bytes1, err := reserializeManifest(m, V2)
		require.NoError(t, err)

		bytes2, err := reserializeManifest(m, V2)
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

// Test with actual embedded testdata (v2 envelope fixture)
func TestDecodeActualManifest(t *testing.T) {
	envelopeBytes := testdata.ManifestBin
	envelopeB64 := base64.StdEncoding.EncodeToString(envelopeBytes)

	env, m, manifestBytes, returnedEnvBytes, err := DecodeManifestEnvelopeFromBase64(envelopeB64, V2)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	assert.NotNil(t, m)
	assert.NotEmpty(t, manifestBytes)
	assert.Equal(t, envelopeBytes, returnedEnvBytes)

	// Envelope hash should be stable
	envelopeHash := ComputeHash(envelopeBytes)
	assert.Len(t, envelopeHash, 64)

	// Manifest should have valid namespace
	assert.NotEmpty(t, m.Namespace.Name)
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

// --- V1 (legacy) decode path tests ---

func TestDecodeV1RawManifest(t *testing.T) {
	v1 := ManifestV1{
		Namespace:   Namespace{Name: "v1-test", Nonce: 100, QuorumKey: []byte{0x01}},
		Pivot:       PivotConfigV1{Restart: RestartPolicyAlways, Args: []string{"--port", "3000"}},
		ManifestSet: ManifestSet{Threshold: 1},
		ShareSet:    ShareSet{Threshold: 2},
		Enclave:     NitroConfig{QosCommit: "v1commit"},
		PatchSet:    PatchSet{Threshold: 1},
	}

	data, err := borsh.Serialize(v1)
	require.NoError(t, err)

	b64 := base64.StdEncoding.EncodeToString(data)

	t.Run("from base64", func(t *testing.T) {
		m, manifestBytes, err := DecodeRawManifestFromBase64(b64, V1)
		require.NoError(t, err)
		require.NotNil(t, m)
		require.NotEmpty(t, manifestBytes)
		require.Equal(t, "v1-test", m.Namespace.Name)
		require.Equal(t, RestartPolicyAlways, m.Pivot.Restart)
		require.Equal(t, []string{"--port", "3000"}, m.Pivot.Args)
		require.Empty(t, m.Pivot.BridgeConfig)
		require.False(t, m.Pivot.DebugMode)
	})

	t.Run("from file", func(t *testing.T) {
		tmpDir := t.TempDir()
		p := filepath.Join(tmpDir, "v1.bin")
		require.NoError(t, os.WriteFile(p, data, 0644))

		m, _, err := DecodeRawManifestFromFile(p, V1)
		require.NoError(t, err)
		require.Equal(t, "v1-test", m.Namespace.Name)
	})
}

func TestDecodeV1Envelope(t *testing.T) {
	v1 := ManifestEnvelopeV1{
		Manifest: ManifestV1{
			Namespace: Namespace{Name: "v1-env", Nonce: 200},
			Pivot:     PivotConfigV1{Restart: RestartPolicyNever, Args: []string{"arg1"}},
		},
		ManifestSetApprovals: []Approval{{Signature: []byte{0xAA}, Member: QuorumMember{Alias: "a1"}}},
		ShareSetApprovals:    []Approval{},
	}

	data, err := borsh.Serialize(v1)
	require.NoError(t, err)

	b64 := base64.StdEncoding.EncodeToString(data)

	t.Run("envelope from base64", func(t *testing.T) {
		env, m, manifestBytes, envBytes, err := DecodeManifestEnvelopeFromBase64(b64, V1)
		require.NoError(t, err)
		require.NotNil(t, env)
		require.NotNil(t, m)
		require.NotEmpty(t, manifestBytes)
		require.Equal(t, data, envBytes)
		require.Equal(t, "v1-env", m.Namespace.Name)
		require.Len(t, env.ManifestSetApprovals, 1)
	})

	t.Run("envelope from file", func(t *testing.T) {
		tmpDir := t.TempDir()
		p := filepath.Join(tmpDir, "v1env.bin")
		require.NoError(t, os.WriteFile(p, data, 0644))

		env, m, _, _, err := DecodeManifestEnvelopeFromFile(p, V1)
		require.NoError(t, err)
		require.Equal(t, "v1-env", m.Namespace.Name)
		require.Len(t, env.ManifestSetApprovals, 1)
	})

	t.Run("DecodeManifestFromBase64 with V1", func(t *testing.T) {
		m, manifestBytes, envBytes, err := DecodeManifestFromBase64(b64, V1)
		require.NoError(t, err)
		require.NotNil(t, m)
		require.NotEmpty(t, manifestBytes)
		require.Equal(t, data, envBytes)
		require.Equal(t, "v1-env", m.Namespace.Name)
	})

	t.Run("DecodeManifestFromFile with V1", func(t *testing.T) {
		tmpDir := t.TempDir()
		p := filepath.Join(tmpDir, "v1file.bin")
		require.NoError(t, os.WriteFile(p, data, 0644))

		m, _, _, err := DecodeManifestFromFile(p, V1)
		require.NoError(t, err)
		require.Equal(t, "v1-env", m.Namespace.Name)
	})
}

func TestDecodeUnknownVersion(t *testing.T) {
	data := []byte{0x01, 0x02}
	b64 := base64.StdEncoding.EncodeToString(data)

	t.Run("raw manifest", func(t *testing.T) {
		_, _, err := DecodeRawManifestFromBase64(b64, ManifestVersion(99))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown manifest version")
	})

	t.Run("envelope", func(t *testing.T) {
		_, _, _, _, err := DecodeManifestEnvelopeFromBase64(b64, ManifestVersion(99))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown manifest version")
	})
}

func TestManifestV1ToManifest(t *testing.T) {
	v0 := ManifestV1{
		Namespace:   Namespace{Name: "convert-test", Nonce: 42, QuorumKey: []byte{0x01, 0x02}},
		Pivot:       PivotConfigV1{Hash: Hash256{0xAA}, Restart: RestartPolicyAlways, Args: []string{"a", "b"}},
		ManifestSet: ManifestSet{Threshold: 3, Members: []QuorumMember{{Alias: "m1", PubKey: []byte{0x10}}}},
		ShareSet:    ShareSet{Threshold: 2, Members: []QuorumMember{{Alias: "s1", PubKey: []byte{0x20}}}},
		Enclave:     NitroConfig{Pcr0: []byte{0x30}, QosCommit: "commit1"},
		PatchSet:    PatchSet{Threshold: 1, Members: []MemberPubKey{{PubKey: []byte{0x40}}}},
	}

	m := v0.ToManifest()

	require.Equal(t, "convert-test", m.Namespace.Name)
	require.Equal(t, uint32(42), m.Namespace.Nonce)
	require.Equal(t, Hash256{0xAA}, m.Pivot.Hash)
	require.Equal(t, RestartPolicyAlways, m.Pivot.Restart)
	require.Equal(t, []string{"a", "b"}, m.Pivot.Args)
	require.Empty(t, m.Pivot.BridgeConfig)
	require.False(t, m.Pivot.DebugMode)
	require.Equal(t, uint32(3), m.ManifestSet.Threshold)
	require.Len(t, m.ManifestSet.Members, 1)
	require.Equal(t, uint32(2), m.ShareSet.Threshold)
	require.Equal(t, []byte{0x30}, m.Enclave.Pcr0)
	require.Equal(t, uint32(1), m.PatchSet.Threshold)
}

func TestManifestEnvelopeV1ToManifestEnvelope(t *testing.T) {
	v0 := ManifestEnvelopeV1{
		Manifest: ManifestV1{
			Namespace: Namespace{Name: "env-convert"},
			Pivot:     PivotConfigV1{Restart: RestartPolicyNever},
		},
		ManifestSetApprovals: []Approval{
			{Signature: []byte{0x11}, Member: QuorumMember{Alias: "a1", PubKey: []byte{0x22}}},
			{Signature: []byte{0x33}, Member: QuorumMember{Alias: "a2", PubKey: []byte{0x44}}},
		},
		ShareSetApprovals: []Approval{
			{Signature: []byte{0x55}, Member: QuorumMember{Alias: "s1", PubKey: []byte{0x66}}},
		},
	}

	env := v0.ToManifestEnvelope()

	require.Equal(t, "env-convert", env.Manifest.Namespace.Name)
	require.Equal(t, RestartPolicyNever, env.Manifest.Pivot.Restart)
	require.Empty(t, env.Manifest.Pivot.BridgeConfig)
	require.Len(t, env.ManifestSetApprovals, 2)
	require.Len(t, env.ShareSetApprovals, 1)
	require.Equal(t, "a1", env.ManifestSetApprovals[0].Member.Alias)
}
