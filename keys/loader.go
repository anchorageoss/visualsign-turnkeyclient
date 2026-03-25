// Package keys provides API key loading and management.
//
// This package implements the api.KeyProvider interface for loading Turnkey API keys
// from the standard Turnkey CLI key storage location.
//
// # Key File Format
//
// Keys are stored in ~/.config/turnkey/keys/ with two files per key:
//
//	<key-name>.public  - Hex-encoded compressed public key
//	<key-name>.private - Format: "hexkey:p256" where hexkey is the private scalar
//
// # Loading Keys
//
// Load an API key using the FileKeyProvider:
//
//	provider := &keys.FileKeyProvider{KeyName: "my-key"}
//	apiKey, err := provider.GetAPIKey(context.Background())
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Or directly load a key by name:
//
//	apiKey, err := keys.LoadAPIKeyFromFile("my-key")
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Key Formats
//
// The private key format in .private file is "hexkey:curve" where:
//   - hexkey: Hex-encoded private key scalar (must be 64 hex characters for P-256)
//   - curve: Curve name (currently only "p256" is supported)
package keys

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchorageoss/visualsign-turnkeyclient/api"
)

// FileKeyProvider implements api.KeyProvider by reading from files
type FileKeyProvider struct {
	KeyName string
}

// GetAPIKey loads the API key from files
func (f *FileKeyProvider) GetAPIKey(ctx context.Context) (*api.TurnkeyAPIKey, error) {
	return LoadAPIKeyFromFile(f.KeyName)
}

// LoadAPIKeyFromFile loads the API key from the Turnkey CLI configuration
func LoadAPIKeyFromFile(keyName string) (*api.TurnkeyAPIKey, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := filepath.Join(homeDir, ".config", "turnkey", "keys")

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
		return nil, errors.New("invalid private key format, expected 'hexkey:curve'")
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

	// Left-pad to 32 bytes for P-256 (hex decoding may produce fewer bytes if leading zeros are omitted)
	if len(privateKeyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privateKeyBytes):], privateKeyBytes)
		privateKeyBytes = padded
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
