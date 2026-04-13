package keys

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadAPIKeyFromPath is a test helper that loads keys from a custom path
func loadAPIKeyFromPath(configDir, keyName string) (*api.TurnkeyAPIKey, error) {
	// Load public key
	publicKeyPath := filepath.Join(configDir, keyName+".public")
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}
	publicKeyHex := strings.TrimSpace(string(publicKeyBytes))

	// Load private key
	privateKeyPath := filepath.Join(configDir, keyName+".private")
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// Parse private key format: "hexkey:curve"
	privateKeyContent := strings.TrimSpace(string(privateKeyBytes))
	parts := strings.Split(privateKeyContent, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid private key format, expected 'hexkey:curve'")
	}

	privateKeyHex := parts[0]
	curve := parts[1]

	if curve != "p256" {
		return nil, fmt.Errorf("unsupported curve: %s, only p256 is supported", curve)
	}

	// Decode hex private key
	privateKeyBytes, err = hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key hex: %w", err)
	}

	// Create ECDSA private key
	ecdsaCurve := elliptic.P256()
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: ecdsaCurve,
		},
		D: new(big.Int).SetBytes(privateKeyBytes),
	}

	// Calculate public key point using crypto/ecdh (non-deprecated API)
	ecdhPrivKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create ecdh private key: %w", err)
	}
	pubBytes := ecdhPrivKey.PublicKey().Bytes()
	privateKey.X = new(big.Int).SetBytes(pubBytes[1:33])
	privateKey.Y = new(big.Int).SetBytes(pubBytes[33:65])

	return &api.TurnkeyAPIKey{
		PublicKey:  publicKeyHex,
		PrivateKey: privateKey,
	}, nil
}

func TestLoadAPIKeyFromFile(t *testing.T) {
	testdataDir := "testdata"

	t.Run("valid key", func(t *testing.T) {
		key, err := loadAPIKeyFromPath(testdataDir, "valid")
		require.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, "02f739f8c77b32f4d5f13265861febd76e7a9c61a1140d296b8c16302508870316", key.PublicKey)
		assert.NotNil(t, key.PrivateKey)

		// Verify private key properties
		assert.Equal(t, elliptic.P256(), key.PrivateKey.Curve)
		expectedD, _ := new(big.Int).SetString("487f361ddfd73440e707f4daa6775b376859e8a3c9f29b3bb694a12927c0213c", 16)
		assert.Equal(t, 0, expectedD.Cmp(key.PrivateKey.D))

		// Verify public key derivation is correct
		assert.NotNil(t, key.PrivateKey.X)
		assert.NotNil(t, key.PrivateKey.Y)
	})

	t.Run("missing public key", func(t *testing.T) {
		_, err := loadAPIKeyFromPath(testdataDir, "missing_public")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read public key file")
	})

	t.Run("missing private key", func(t *testing.T) {
		_, err := loadAPIKeyFromPath(testdataDir, "missing_private")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read private key file")
	})

	t.Run("invalid hex in private key", func(t *testing.T) {
		_, err := loadAPIKeyFromPath(testdataDir, "invalid_hex")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode private key hex")
	})

	t.Run("wrong curve", func(t *testing.T) {
		_, err := loadAPIKeyFromPath(testdataDir, "wrong_curve")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported curve: secp256k1")
	})

	t.Run("bad format", func(t *testing.T) {
		_, err := loadAPIKeyFromPath(testdataDir, "bad_format")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid private key format")
	})

	t.Run("non-existent key", func(t *testing.T) {
		_, err := loadAPIKeyFromPath(testdataDir, "does_not_exist")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read public key file")
	})
}

func TestFileKeyProvider(t *testing.T) {
	// Test the FileKeyProvider interface implementation
	// This test would normally require setting up proper ~/.config/turnkey/keys
	// For unit tests, we'll test the structure and error handling

	t.Run("provider structure", func(t *testing.T) {
		provider := &FileKeyProvider{KeyName: "test-key"}
		assert.Equal(t, "test-key", provider.KeyName)
	})

	t.Run("GetAPIKey calls LoadAPIKeyFromFile", func(t *testing.T) {
		provider := &FileKeyProvider{KeyName: "non-existent-key"}
		// This will fail because the key doesn't exist in ~/.config/turnkey/keys
		_, err := provider.GetAPIKey(context.Background())
		assert.Error(t, err)
		// The error should come from LoadAPIKeyFromFile
		assert.Contains(t, err.Error(), "failed to read")
	})
}

func TestKeyDerivation(t *testing.T) {
	// Test that the public key is correctly derived from the private key
	testdataDir := "testdata"

	key, err := loadAPIKeyFromPath(testdataDir, "valid")
	require.NoError(t, err)

	// Verify that X,Y are on the curve using crypto/ecdh (non-deprecated API)
	ecdhKey, err := key.PrivateKey.ECDH()
	require.NoError(t, err)
	_, err = ecdh.P256().NewPublicKey(ecdhKey.PublicKey().Bytes())
	assert.NoError(t, err, "Public key point should be on the curve")

	// Verify the public key can be reconstructed using crypto/ecdh
	privateBytes := key.PrivateKey.D.Bytes()
	if len(privateBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privateBytes):], privateBytes)
		privateBytes = padded
	}
	ecdhPrivKey, err := ecdh.P256().NewPrivateKey(privateBytes)
	require.NoError(t, err)
	derivedPubBytes := ecdhPrivKey.PublicKey().Bytes()
	x := new(big.Int).SetBytes(derivedPubBytes[1:33])
	y := new(big.Int).SetBytes(derivedPubBytes[33:65])
	assert.Equal(t, 0, x.Cmp(key.PrivateKey.X), "X coordinate should match")
	assert.Equal(t, 0, y.Cmp(key.PrivateKey.Y), "Y coordinate should match")
}

func TestPublicKeyFormat(t *testing.T) {
	// Test that public keys are in the expected compressed format
	testdataDir := "testdata"

	key, err := loadAPIKeyFromPath(testdataDir, "valid")
	require.NoError(t, err)

	// Public key should be 66 hex chars (33 bytes) for compressed P-256
	assert.Len(t, key.PublicKey, 66, "Compressed P-256 public key should be 66 hex characters")

	// Should start with 02 or 03 (compressed format prefix)
	assert.True(t, strings.HasPrefix(key.PublicKey, "02") || strings.HasPrefix(key.PublicKey, "03"),
		"Compressed public key should start with 02 or 03")

	// Should be valid hex
	_, err = hex.DecodeString(key.PublicKey)
	assert.NoError(t, err, "Public key should be valid hex")
}

func TestLoadAPIKeyFromFileIntegration(t *testing.T) {
	// Integration test that uses the actual LoadAPIKeyFromFile function
	// This requires setting up a temporary home directory structure

	t.Run("with temp home dir", func(t *testing.T) {
		// Create temp directory structure
		tmpDir := t.TempDir()
		configDir := filepath.Join(tmpDir, ".config", "turnkey", "keys")
		err := os.MkdirAll(configDir, 0755)
		require.NoError(t, err)

		// Copy test files to temp location
		validPublic, err := os.ReadFile("testdata/valid.public")
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(configDir, "test-key.public"), validPublic, 0644)
		require.NoError(t, err)

		validPrivate, err := os.ReadFile("testdata/valid.private")
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(configDir, "test-key.private"), validPrivate, 0644)
		require.NoError(t, err)

		t.Setenv("HOME", tmpDir)

		// Test LoadAPIKeyFromFile
		key, err := LoadAPIKeyFromFile("test-key")
		assert.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, "02f739f8c77b32f4d5f13265861febd76e7a9c61a1140d296b8c16302508870316", key.PublicKey)
	})
}

func TestLoadAPIKeyEdgeCases(t *testing.T) {
	t.Run("short private key needs padding", func(t *testing.T) {
		// Use LoadAPIKeyFromFile (not the test helper) since only it has padding logic
		tmpDir := t.TempDir()
		configDir := filepath.Join(tmpDir, ".config", "turnkey", "keys")
		require.NoError(t, os.MkdirAll(configDir, 0755))

		// 62 hex chars = 31 bytes → triggers left-padding to 32 bytes
		shortKey := "7f361ddfd73440e707f4daa6775b376859e8a3c9f29b3bb694a12927c0213c"
		require.NoError(t, os.WriteFile(filepath.Join(configDir, "short.public"), []byte("02aabbccdd"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(configDir, "short.private"), []byte(shortKey+":p256"), 0644))

		t.Setenv("HOME", tmpDir)

		key, err := LoadAPIKeyFromFile("short")
		require.NoError(t, err)
		require.NotNil(t, key)
		require.NotNil(t, key.PrivateKey)
	})

	t.Run("invalid private key format", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := os.WriteFile(filepath.Join(tmpDir, "bad.public"), []byte("02aabb"), 0644)
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(tmpDir, "bad.private"), []byte("nocolon"), 0644)
		require.NoError(t, err)

		_, err = loadAPIKeyFromPath(tmpDir, "bad")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid private key format")
	})

	t.Run("unsupported curve", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := os.WriteFile(filepath.Join(tmpDir, "curve.public"), []byte("02aabb"), 0644)
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(tmpDir, "curve.private"), []byte("aabb:secp256k1"), 0644)
		require.NoError(t, err)

		_, err = loadAPIKeyFromPath(tmpDir, "curve")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported curve")
	})

	t.Run("invalid hex in private key", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := os.WriteFile(filepath.Join(tmpDir, "hex.public"), []byte("02aabb"), 0644)
		require.NoError(t, err)
		err = os.WriteFile(filepath.Join(tmpDir, "hex.private"), []byte("ZZZZ:p256"), 0644)
		require.NoError(t, err)

		_, err = loadAPIKeyFromPath(tmpDir, "hex")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode private key hex")
	})

	t.Run("missing public key file", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := os.WriteFile(filepath.Join(tmpDir, "nopub.private"), []byte("aabb:p256"), 0644)
		require.NoError(t, err)

		_, err = loadAPIKeyFromPath(tmpDir, "nopub")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read public key")
	})

	t.Run("missing private key file", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := os.WriteFile(filepath.Join(tmpDir, "nopriv.public"), []byte("02aabb"), 0644)
		require.NoError(t, err)

		_, err = loadAPIKeyFromPath(tmpDir, "nopriv")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read private key")
	})
}

// Benchmarks to match patterns from tkhq/go-sdk
func BenchmarkLoadAPIKey(b *testing.B) {
	testdataDir := "testdata"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := loadAPIKeyFromPath(testdataDir, "valid")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeyDerivation(b *testing.B) {
	privateKeyHex := "487f361ddfd73440e707f4daa6775b376859e8a3c9f29b3bb694a12927c0213c"
	privateKeyBytes, _ := hex.DecodeString(privateKeyHex)

	ecdhPrivKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ecdhPrivKey.PublicKey()
	}
}
