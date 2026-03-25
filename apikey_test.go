package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/crypto"
	"github.com/anchorageoss/visualsign-turnkeyclient/keys"
	"github.com/stretchr/testify/require"
)

// TestLoadAPIKeyFromFile tests loading a valid API key from files
func TestLoadAPIKeyFromFile(t *testing.T) {
	// Generate a test key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create test directory
	tempDir := t.TempDir()
	keyName := "test-key"

	// Create .public file
	publicKeyHex := hex.EncodeToString(privKey.X.Bytes())
	publicKeyPath := filepath.Join(tempDir, keyName+".public")
	err = os.WriteFile(publicKeyPath, []byte(publicKeyHex), 0o644)
	require.NoError(t, err)

	// Create .private file (format: hexkey:curve)
	d := privKey.D.Bytes()
	// Pad to 32 bytes for P-256
	dPadded := make([]byte, 32)
	copy(dPadded[32-len(d):], d)
	privateKeyHex := hex.EncodeToString(dPadded)
	privateKeyContent := privateKeyHex + ":p256"
	privateKeyPath := filepath.Join(tempDir, keyName+".private")
	err = os.WriteFile(privateKeyPath, []byte(privateKeyContent), 0o644)
	require.NoError(t, err)

	// Create mock .config/turnkey/keys directory structure
	configDir := filepath.Join(tempDir, ".config", "turnkey", "keys")
	err = os.MkdirAll(configDir, 0o755)
	require.NoError(t, err)

	// Copy test files to the expected location
	sourcePublic := filepath.Join(tempDir, keyName+".public")
	targetPublic := filepath.Join(configDir, keyName+".public")
	publicData, err := os.ReadFile(sourcePublic)
	require.NoError(t, err)
	err = os.WriteFile(targetPublic, publicData, 0o644)
	require.NoError(t, err)

	sourcePrivate := filepath.Join(tempDir, keyName+".private")
	targetPrivate := filepath.Join(configDir, keyName+".private")
	privateData, err := os.ReadFile(sourcePrivate)
	require.NoError(t, err)
	err = os.WriteFile(targetPrivate, privateData, 0o644)
	require.NoError(t, err)

	// Set HOME to temp directory
	t.Setenv("HOME", tempDir)

	// Load the key
	apiKey, err := keys.LoadAPIKeyFromFile(keyName)
	require.NoError(t, err)
	require.NotNil(t, apiKey)
	require.NotNil(t, apiKey.PrivateKey)
	require.NotEmpty(t, apiKey.PublicKey)
}

// TestLoadAPIKeyMissingPublicKey tests error handling when public key file is missing
func TestLoadAPIKeyMissingPublicKey(t *testing.T) {
	tempDir := t.TempDir()
	keyName := "missing-public"

	// Create only private key file
	configDir := filepath.Join(tempDir, ".config", "turnkey", "keys")
	err := os.MkdirAll(configDir, 0o755)
	require.NoError(t, err)

	privateKeyPath := filepath.Join(configDir, keyName+".private")
	err = os.WriteFile(privateKeyPath, []byte("deadbeef:p256"), 0o644)
	require.NoError(t, err)

	// Override home directory
	t.Setenv("HOME", tempDir)

	// Should fail
	apiKey, err := keys.LoadAPIKeyFromFile(keyName)
	require.Error(t, err)
	require.Nil(t, apiKey)
	require.Contains(t, err.Error(), "failed to read public key file")
}

// TestLoadAPIKeyMissingPrivateKey tests error handling when private key file is missing
func TestLoadAPIKeyMissingPrivateKey(t *testing.T) {
	tempDir := t.TempDir()
	keyName := "missing-private"

	// Create only public key file
	configDir := filepath.Join(tempDir, ".config", "turnkey", "keys")
	err := os.MkdirAll(configDir, 0o755)
	require.NoError(t, err)

	publicKeyPath := filepath.Join(configDir, keyName+".public")
	err = os.WriteFile(publicKeyPath, []byte("cafebabe"), 0o644)
	require.NoError(t, err)

	// Override home directory
	t.Setenv("HOME", tempDir)

	// Should fail
	apiKey, err := keys.LoadAPIKeyFromFile(keyName)
	require.Error(t, err)
	require.Nil(t, apiKey)
	require.Contains(t, err.Error(), "failed to read private key file")
}

// TestLoadAPIKeyInvalidPrivateKeyFormat tests error handling for invalid key format
func TestLoadAPIKeyInvalidPrivateKeyFormat(t *testing.T) {
	tempDir := t.TempDir()
	keyName := "invalid-format"

	// Create configuration directory
	configDir := filepath.Join(tempDir, ".config", "turnkey", "keys")
	err := os.MkdirAll(configDir, 0o755)
	require.NoError(t, err)

	// Create public key file
	publicKeyPath := filepath.Join(configDir, keyName+".public")
	err = os.WriteFile(publicKeyPath, []byte("cafebabe"), 0o644)
	require.NoError(t, err)

	// Create private key file with invalid format (missing :curve part)
	privateKeyPath := filepath.Join(configDir, keyName+".private")
	err = os.WriteFile(privateKeyPath, []byte("deadbeefdeadbeef"), 0o644)
	require.NoError(t, err)

	// Override home directory
	t.Setenv("HOME", tempDir)

	// Should fail
	apiKey, err := keys.LoadAPIKeyFromFile(keyName)
	require.Error(t, err)
	require.Nil(t, apiKey)
	require.Contains(t, err.Error(), "invalid private key format")
}

// TestLoadAPIKeyUnsupportedCurve tests error handling for unsupported curves
func TestLoadAPIKeyUnsupportedCurve(t *testing.T) {
	tempDir := t.TempDir()
	keyName := "unsupported-curve"

	// Create configuration directory
	configDir := filepath.Join(tempDir, ".config", "turnkey", "keys")
	err := os.MkdirAll(configDir, 0o755)
	require.NoError(t, err)

	// Create public key file
	publicKeyPath := filepath.Join(configDir, keyName+".public")
	err = os.WriteFile(publicKeyPath, []byte("cafebabe"), 0o644)
	require.NoError(t, err)

	// Create private key file with unsupported curve (p384)
	privateKeyPath := filepath.Join(configDir, keyName+".private")
	err = os.WriteFile(privateKeyPath, []byte("deadbeef:p384"), 0o644)
	require.NoError(t, err)

	// Override home directory
	t.Setenv("HOME", tempDir)

	// Should fail
	apiKey, err := keys.LoadAPIKeyFromFile(keyName)
	require.Error(t, err)
	require.Nil(t, apiKey)
	require.Contains(t, err.Error(), "unsupported curve")
}

// TestLoadAPIKeyInvalidHex tests error handling for invalid hex in private key
func TestLoadAPIKeyInvalidHex(t *testing.T) {
	tempDir := t.TempDir()
	keyName := "invalid-hex"

	// Create configuration directory
	configDir := filepath.Join(tempDir, ".config", "turnkey", "keys")
	err := os.MkdirAll(configDir, 0o755)
	require.NoError(t, err)

	// Create public key file
	publicKeyPath := filepath.Join(configDir, keyName+".public")
	err = os.WriteFile(publicKeyPath, []byte("cafebabe"), 0o644)
	require.NoError(t, err)

	// Create private key file with invalid hex
	privateKeyPath := filepath.Join(configDir, keyName+".private")
	err = os.WriteFile(privateKeyPath, []byte("not_valid_hex_here:p256"), 0o644)
	require.NoError(t, err)

	// Override home directory
	t.Setenv("HOME", tempDir)

	// Should fail
	apiKey, err := keys.LoadAPIKeyFromFile(keyName)
	require.Error(t, err)
	require.Nil(t, apiKey)
	require.Contains(t, err.Error(), "failed to decode private key hex")
}

// TestFileAPIKeyProvider tests the APIKeyProvider interface
func TestFileAPIKeyProvider(t *testing.T) {
	// Generate a test key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tempDir := t.TempDir()
	keyName := "provider-test"

	// Create configuration directory
	configDir := filepath.Join(tempDir, ".config", "turnkey", "keys")
	err = os.MkdirAll(configDir, 0o755)
	require.NoError(t, err)

	// Create public key file
	publicKeyPath := filepath.Join(configDir, keyName+".public")
	err = os.WriteFile(publicKeyPath, []byte("cafebabe"), 0o644)
	require.NoError(t, err)

	// Create private key file
	d := privKey.D.Bytes()
	dPadded := make([]byte, 32)
	copy(dPadded[32-len(d):], d)
	privateKeyHex := hex.EncodeToString(dPadded)
	privateKeyContent := privateKeyHex + ":p256"
	privateKeyPath := filepath.Join(configDir, keyName+".private")
	err = os.WriteFile(privateKeyPath, []byte(privateKeyContent), 0o644)
	require.NoError(t, err)

	// Override home directory
	t.Setenv("HOME", tempDir)

	// Create provider
	provider := &keys.FileKeyProvider{KeyName: keyName}

	// Get API key through provider
	apiKey, err := provider.GetAPIKey(context.Background())
	require.NoError(t, err)
	require.NotNil(t, apiKey)
	require.NotNil(t, apiKey.PrivateKey)
}

// TestASN1MarshalECDSASignature tests ECDSA signature marshaling
func TestASN1MarshalECDSASignature(t *testing.T) {
	tests := []struct {
		name    string
		r, s    *big.Int
		wantErr bool
	}{
		{
			name:    "valid signature components",
			r:       big.NewInt(12345),
			s:       big.NewInt(67890),
			wantErr: false,
		},
		{
			name:    "zero r",
			r:       big.NewInt(0),
			s:       big.NewInt(67890),
			wantErr: false,
		},
		{
			name:    "large numbers",
			r:       new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}),
			s:       new(big.Int).SetBytes([]byte{0xFF, 0xFF, 0xFF, 0xFF}),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := crypto.MarshalECDSASignatureDER(tt.r, tt.s)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, sig)
				// Should be DER encoded, starts with SEQUENCE tag (0x30)
				require.Equal(t, byte(0x30), sig[0])
			}
		})
	}
}

// TestAPIKeyPrivateKeyProperties tests that loaded private key has correct properties
func TestAPIKeyPrivateKeyProperties(t *testing.T) {
	// Generate a test key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tempDir := t.TempDir()
	keyName := "properties-test"

	// Create configuration directory
	configDir := filepath.Join(tempDir, ".config", "turnkey", "keys")
	err = os.MkdirAll(configDir, 0o755)
	require.NoError(t, err)

	// Create public key file
	publicKeyHex := hex.EncodeToString(privKey.X.Bytes())
	publicKeyPath := filepath.Join(configDir, keyName+".public")
	err = os.WriteFile(publicKeyPath, []byte(publicKeyHex), 0o644)
	require.NoError(t, err)

	// Create private key file
	d := privKey.D.Bytes()
	dPadded := make([]byte, 32)
	copy(dPadded[32-len(d):], d)
	privateKeyHex := hex.EncodeToString(dPadded)
	privateKeyContent := privateKeyHex + ":p256"
	privateKeyPath := filepath.Join(configDir, keyName+".private")
	err = os.WriteFile(privateKeyPath, []byte(privateKeyContent), 0o644)
	require.NoError(t, err)

	// Override home directory
	t.Setenv("HOME", tempDir)

	// Load the key
	apiKey, err := keys.LoadAPIKeyFromFile(keyName)
	require.NoError(t, err)

	// Verify private key properties
	require.NotNil(t, apiKey.PrivateKey.D)
	require.NotNil(t, apiKey.PrivateKey.X)
	require.NotNil(t, apiKey.PrivateKey.Y)
	require.Equal(t, elliptic.P256(), apiKey.PrivateKey.Curve)

	// Verify public key is on the curve using crypto/ecdh (non-deprecated API)
	ecdhKey, err := apiKey.PrivateKey.ECDH()
	require.NoError(t, err)
	_, err = ecdh.P256().NewPublicKey(ecdhKey.PublicKey().Bytes())
	require.NoError(t, err)
}
