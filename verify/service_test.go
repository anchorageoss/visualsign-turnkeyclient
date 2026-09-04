package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nitroverifier "github.com/anchorageoss/awsnitroverifier"
	"github.com/anchorageoss/visualsign-turnkeyclient/api"
	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
	"github.com/anchorageoss/visualsign-turnkeyclient/testdata"
	"github.com/near/borsh-go"
	"github.com/stretchr/testify/require"
)

// Helper to create valid 130-byte public key format
func create130BytePublicKey(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKey := privKey.PublicKey
	x := pubKey.X.Bytes()
	y := pubKey.Y.Bytes()

	// Pad to 32 bytes
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(x):], x)
	copy(yPadded[32-len(y):], y)

	// Create 130-byte format (duplicate public key)
	pubKeyBytes130 := make([]byte, 130)
	pubKeyBytes130[0] = 0x04
	copy(pubKeyBytes130[1:33], xPadded)
	copy(pubKeyBytes130[33:65], yPadded)
	pubKeyBytes130[65] = 0x04
	copy(pubKeyBytes130[66:98], xPadded)
	copy(pubKeyBytes130[98:130], yPadded)

	return pubKeyBytes130, privKey
}

// expectedMessageHex returns the appAttestation.Message value the
// VerifyResponse Borsh hash check expects for the given response fields.
// Tests that aren't about the Borsh binding itself use this to bypass it.
func expectedMessageHex(t *testing.T, signablePayload, inputDigest, metadataDigest string) string {
	t.Helper()
	msg, err := ComputeBorshParsedTransactionPayloadHash(signablePayload, inputDigest, metadataDigest, nil)
	require.NoError(t, err)
	return msg
}

// Mock implementations

type mockAPIClient struct {
	response *api.SignablePayloadResponse
	err      error
}

func (m *mockAPIClient) CreateSignablePayload(ctx context.Context, req *api.CreateSignablePayloadRequest) (*api.SignablePayloadResponse, error) {
	return m.response, m.err
}

type mockAttestationVerifier struct {
	result *nitroverifier.ValidationResult
	err    error
}

func (m *mockAttestationVerifier) Validate(attestationDocument []byte) (*nitroverifier.ValidationResult, error) {
	return m.result, m.err
}

// Test NewService
func TestNewService(t *testing.T) {
	apiClient := &mockAPIClient{}
	verifier := &mockAttestationVerifier{}

	service := NewService(apiClient, verifier)

	require.NotNil(t, service)
	require.Equal(t, apiClient, service.apiClient)
	require.Equal(t, verifier, service.attestationVerifier)
}

// Test extractAttestations
func TestExtractAttestations(t *testing.T) {
	service := NewService(&mockAPIClient{}, &mockAttestationVerifier{})

	t.Run("successful extraction", func(t *testing.T) {
		appAttJSON := `{"message":"msg","publicKey":"key","signature":"sig"}`
		response := &api.SignablePayloadResponse{
			Attestations: map[api.AttestationType]string{
				api.AppAttestationKey:  appAttJSON,
				api.BootAttestationKey: "boot-doc",
			},
		}

		appAtt, bootDoc, err := service.extractAttestations(response)
		require.NoError(t, err)
		require.Equal(t, "msg", appAtt.Message)
		require.Equal(t, "key", appAtt.PublicKey)
		require.Equal(t, "sig", appAtt.Signature)
		require.Equal(t, "boot-doc", bootDoc)
	})

	t.Run("missing app attestation", func(t *testing.T) {
		response := &api.SignablePayloadResponse{
			Attestations: map[api.AttestationType]string{
				api.BootAttestationKey: "boot-doc",
			},
		}

		_, _, err := service.extractAttestations(response)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no app attestation found")
	})

	t.Run("missing boot attestation", func(t *testing.T) {
		appAttJSON := `{"message":"msg","publicKey":"key","signature":"sig"}`
		response := &api.SignablePayloadResponse{
			Attestations: map[api.AttestationType]string{
				api.AppAttestationKey: appAttJSON,
			},
		}

		_, _, err := service.extractAttestations(response)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no boot attestation found")
	})

	t.Run("invalid app attestation JSON", func(t *testing.T) {
		response := &api.SignablePayloadResponse{
			Attestations: map[api.AttestationType]string{
				api.AppAttestationKey:  "invalid json",
				api.BootAttestationKey: "boot-doc",
			},
		}

		_, _, err := service.extractAttestations(response)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse app attestation")
	})
}

// Test extractPublicKey
func TestExtractPublicKey(t *testing.T) {
	service := NewService(&mockAPIClient{}, &mockAttestationVerifier{})

	t.Run("valid 260-char hex key", func(t *testing.T) {
		pubKeyBytes, _ := create130BytePublicKey(t)
		key260 := hex.EncodeToString(pubKeyBytes)

		pubKey, err := service.extractPublicKey(key260)
		require.NoError(t, err)
		require.NotNil(t, pubKey)
	})

	t.Run("invalid hex", func(t *testing.T) {
		invalidKey := strings.Repeat("ZZ", 130)
		_, err := service.extractPublicKey(invalidKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode public key hex")
	})

	t.Run("invalid key length", func(t *testing.T) {
		// Valid hex but wrong length
		shortKey := strings.Repeat("aa", 50) // 100 hex chars = 50 bytes, not 130
		_, err := service.extractPublicKey(shortKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected 130-byte public key")
	})

	t.Run("invalid prefix on latter 65 bytes", func(t *testing.T) {
		pubKeyBytes, _ := create130BytePublicKey(t)
		pubKeyBytes[65] = 0x05 // Change prefix of latter 65 bytes
		key260 := hex.EncodeToString(pubKeyBytes)

		_, err := service.extractPublicKey(key260)
		require.Error(t, err)
		require.Contains(t, err.Error(), "expected uncompressed public key format")
	})

	t.Run("off-curve point", func(t *testing.T) {
		// Create invalid point
		invalidBytes := make([]byte, 130)
		invalidBytes[0] = 0x04
		invalidBytes[65] = 0x04
		// Leave X,Y as zeros - not a valid curve point
		key260 := hex.EncodeToString(invalidBytes)

		_, err := service.extractPublicKey(key260)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not on the P256 curve")
	})
}

// Test verifyUserData
func TestVerifyUserData(t *testing.T) {
	service := NewService(&mockAPIClient{}, &mockAttestationVerifier{})

	t.Run("empty expected hash with non-empty userData", func(t *testing.T) {
		err := service.verifyUserData([]byte{0xde, 0xad}, "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "hash mismatch")
	})

	t.Run("empty expected hash with empty userData", func(t *testing.T) {
		err := service.verifyUserData([]byte{}, "")
		require.NoError(t, err)
	})

	t.Run("matching hash", func(t *testing.T) {
		userData := []byte{0xde, 0xad, 0xbe, 0xef}
		expectedHash := "deadbeef" // hex of userData

		err := service.verifyUserData(userData, expectedHash)
		require.NoError(t, err)
	})

	t.Run("non-matching hash", func(t *testing.T) {
		userData := []byte{0xde, 0xad, 0xbe, 0xef}
		expectedHash := "ffffffff"

		err := service.verifyUserData(userData, expectedHash)
		require.Error(t, err)
		require.Contains(t, err.Error(), "hash mismatch")
	})

	t.Run("invalid hex in expected hash", func(t *testing.T) {
		userData := []byte{0xde, 0xad}
		expectedHash := "ZZZZ"

		err := service.verifyUserData(userData, expectedHash)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid hash hex")
	})
}

// TestVerifyChainMetadataRequiresChain ensures that setting ChainMetadata
// without an explicit Chain returns an error rather than silently defaulting
// to CHAIN_SOLANA.
func TestVerifyChainMetadataRequiresChain(t *testing.T) {
	service := NewService(&mockAPIClient{}, &mockAttestationVerifier{})
	networkID := "1"
	req := &VerifyRequest{
		UnsignedPayload: "unsigned-payload",
		// Chain intentionally empty
		ChainMetadata: &api.RequestChainMetadata{
			Ethereum: &api.EthereumChainMetadata{NetworkID: &networkID},
		},
	}
	_, err := service.Verify(context.Background(), req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "chain must be specified")
}

// TestVerifyEthereumMetadataRequiresEthereumChain ensures that providing
// Ethereum chain metadata alongside a non-Ethereum chain returns an error.
func TestVerifyEthereumMetadataRequiresEthereumChain(t *testing.T) {
	service := NewService(&mockAPIClient{}, &mockAttestationVerifier{})
	networkID := "1"
	req := &VerifyRequest{
		UnsignedPayload: "unsigned-payload",
		Chain:           "CHAIN_SOLANA",
		ChainMetadata: &api.RequestChainMetadata{
			Ethereum: &api.EthereumChainMetadata{NetworkID: &networkID},
		},
	}
	_, err := service.Verify(context.Background(), req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ChainMetadata.Ethereum requires an Ethereum chain")
}

// Test Verify - API error
func TestVerifyAPIError(t *testing.T) {
	mockAPI := &mockAPIClient{err: fmt.Errorf("API error")}
	mockVerifier := &mockAttestationVerifier{}

	service := NewService(mockAPI, mockVerifier)

	req := &VerifyRequest{
		UnsignedPayload: "unsigned-payload",
	}

	result, err := service.Verify(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "failed to call API")
}

// Test Verify - attestation validation error
func TestVerifyAttestationError(t *testing.T) {
	pubKeyBytes, _ := create130BytePublicKey(t)
	validKey260 := hex.EncodeToString(pubKeyBytes)
	messageHex := expectedMessageHex(t, "test-payload", "", "")
	signatureHex := strings.Repeat("cd", 64)
	appAttJSON := fmt.Sprintf(`{"message":"%s","publicKey":"%s","signature":"%s"}`, messageHex, validKey260, signatureHex)

	// Use valid base64 for boot attestation
	bootAttestationB64 := base64.StdEncoding.EncodeToString([]byte("boot-doc"))

	apiResponse := &api.SignablePayloadResponse{
		SignablePayload: "test-payload",
		Attestations: map[api.AttestationType]string{
			api.AppAttestationKey:  appAttJSON,
			api.BootAttestationKey: bootAttestationB64,
		},
	}

	mockAPI := &mockAPIClient{response: apiResponse}
	mockVerifier := &mockAttestationVerifier{err: fmt.Errorf("validation error")}

	service := NewService(mockAPI, mockVerifier)

	req := &VerifyRequest{
		UnsignedPayload: "unsigned-payload",
	}

	result, err := service.Verify(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "failed to verify attestation document")
}

// Test Verify - invalid attestation result
func TestVerifyInvalidAttestation(t *testing.T) {
	pubKeyBytes, _ := create130BytePublicKey(t)
	validKey260 := hex.EncodeToString(pubKeyBytes)
	messageHex := expectedMessageHex(t, "test-payload", "", "")
	signatureHex := strings.Repeat("fe", 64)
	appAttJSON := fmt.Sprintf(`{"message":"%s","publicKey":"%s","signature":"%s"}`, messageHex, validKey260, signatureHex)

	// Use valid base64 for boot attestation
	bootAttestationB64 := base64.StdEncoding.EncodeToString([]byte("boot-doc"))

	apiResponse := &api.SignablePayloadResponse{
		SignablePayload: "test-payload",
		Attestations: map[api.AttestationType]string{
			api.AppAttestationKey:  appAttJSON,
			api.BootAttestationKey: bootAttestationB64,
		},
	}

	mockAPI := &mockAPIClient{response: apiResponse}
	mockVerifier := &mockAttestationVerifier{
		result: &nitroverifier.ValidationResult{
			Valid: false,
		},
	}

	service := NewService(mockAPI, mockVerifier)

	req := &VerifyRequest{
		UnsignedPayload: "unsigned-payload",
	}

	result, err := service.Verify(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "attestation document validation failed")
}

// Test Verify with SaveManifestPath
func TestVerifySaveManifest(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "manifest.bin")

	manifestEnvelopeB64 := base64.StdEncoding.EncodeToString([]byte("test-manifest-data"))
	pubKeyBytes, _ := create130BytePublicKey(t)
	validKey260 := hex.EncodeToString(pubKeyBytes)
	messageHex := strings.Repeat("dd", 32)
	signatureHex := strings.Repeat("ef", 64)
	appAttJSON := fmt.Sprintf(`{"message":"%s","publicKey":"%s","signature":"%s"}`, messageHex, validKey260, signatureHex)

	apiResponse := &api.SignablePayloadResponse{
		SignablePayload:        "test-payload",
		QosManifestEnvelopeB64: manifestEnvelopeB64,
		Attestations: map[api.AttestationType]string{
			api.AppAttestationKey:  appAttJSON,
			api.BootAttestationKey: "boot-doc",
		},
	}

	mockAPI := &mockAPIClient{response: apiResponse}
	mockVerifier := &mockAttestationVerifier{
		result: &nitroverifier.ValidationResult{
			Valid: true,
			Document: &nitroverifier.AttestationDocument{
				ModuleID: "test-module",
				PCRs:     map[uint][]byte{},
				UserData: []byte{},
			},
		},
	}

	service := NewService(mockAPI, mockVerifier)

	req := &VerifyRequest{
		UnsignedPayload:  "unsigned-payload",
		SaveManifestPath: manifestPath,
	}

	// This will fail at signature verification, but manifest should still be saved
	_, err := service.Verify(context.Background(), req)
	require.Error(t, err) // Expected to fail at signature verification

	// Verify manifest was saved before failure
	savedData, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	require.Equal(t, []byte("test-manifest-data"), savedData)
}

// Test Verify - missing attestations
func TestVerifyMissingAttestations(t *testing.T) {
	apiResponse := &api.SignablePayloadResponse{
		SignablePayload: "test-payload",
		Attestations:    map[api.AttestationType]string{},
	}

	mockAPI := &mockAPIClient{response: apiResponse}
	mockVerifier := &mockAttestationVerifier{}

	service := NewService(mockAPI, mockVerifier)

	req := &VerifyRequest{
		UnsignedPayload: "unsigned-payload",
	}

	result, err := service.Verify(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "no app attestation found")
}

// Test Verify - invalid public key in attestation
func TestVerifyInvalidPublicKey(t *testing.T) {
	// 130-byte buffer whose SEC1 half has the valid 0x04 prefix but X,Y = 0.
	// That clears both the Borsh message check and the pubkey-binding check
	// (Document.PublicKey is set to the same bytes), so failure surfaces in
	// extractPublicKey's on-curve check — the path this test is named for.
	invalidPubKey := make([]byte, 130)
	invalidPubKey[65] = 0x04
	invalidPubKeyHex := hex.EncodeToString(invalidPubKey)
	messageHex := expectedMessageHex(t, "test-payload", "", "")
	bootAttestationB64 := base64.StdEncoding.EncodeToString([]byte("boot-doc"))

	appAttJSON := fmt.Sprintf(`{"message":"%s","publicKey":"%s","signature":"%s"}`,
		messageHex, invalidPubKeyHex, strings.Repeat("ab", 64))

	apiResponse := &api.SignablePayloadResponse{
		SignablePayload: "test-payload",
		Attestations: map[api.AttestationType]string{
			api.AppAttestationKey:  appAttJSON,
			api.BootAttestationKey: bootAttestationB64,
		},
	}

	mockAPI := &mockAPIClient{response: apiResponse}
	mockVerifier := &mockAttestationVerifier{
		result: &nitroverifier.ValidationResult{
			Valid: true,
			Document: &nitroverifier.AttestationDocument{
				ModuleID:  "test-module",
				PCRs:      map[uint][]byte{},
				UserData:  []byte{},
				PublicKey: invalidPubKey,
			},
		},
	}

	service := NewService(mockAPI, mockVerifier)

	req := &VerifyRequest{
		UnsignedPayload: "unsigned-payload",
	}

	result, err := service.Verify(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "not on the P256 curve")
}

// Test Verify - invalid signature hex.
func TestVerifyInvalidSignatureHex(t *testing.T) {
	pubKeyBytes, _ := create130BytePublicKey(t)
	validKey260 := hex.EncodeToString(pubKeyBytes)
	messageHex := expectedMessageHex(t, "test-payload", "", "")

	appAttJSON := fmt.Sprintf(`{"message":"%s","publicKey":"%s","signature":"ZZZZ"}`, messageHex, validKey260)

	// Use valid base64 for boot attestation
	bootAttestationB64 := base64.StdEncoding.EncodeToString([]byte("boot-doc"))

	apiResponse := &api.SignablePayloadResponse{
		SignablePayload: "test-payload",
		Attestations: map[api.AttestationType]string{
			api.AppAttestationKey:  appAttJSON,
			api.BootAttestationKey: bootAttestationB64,
		},
	}

	mockAPI := &mockAPIClient{response: apiResponse}
	mockVerifier := &mockAttestationVerifier{
		result: &nitroverifier.ValidationResult{
			Valid: true,
			Document: &nitroverifier.AttestationDocument{
				ModuleID:  "test-module",
				PCRs:      map[uint][]byte{},
				UserData:  []byte{},
				PublicKey: pubKeyBytes,
			},
		},
	}

	service := NewService(mockAPI, mockVerifier)

	req := &VerifyRequest{
		UnsignedPayload: "unsigned-payload",
	}

	result, err := service.Verify(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "failed to decode signature hex")
}

// Test Verify - default chain value
func TestVerifyDefaultChain(t *testing.T) {
	mockAPI := &mockAPIClient{err: fmt.Errorf("API error")}
	mockVerifier := &mockAttestationVerifier{}

	service := NewService(mockAPI, mockVerifier)

	// Test that empty chain triggers default handling
	req := &VerifyRequest{
		UnsignedPayload: "unsigned-payload",
		Chain:           "", // Should default to CHAIN_SOLANA
	}

	_, err := service.Verify(context.Background(), req)
	require.Error(t, err)
	// The API will be called with CHAIN_SOLANA default, but we don't test that here
	// We just verify the function handles empty chain correctly
}

// Test Verify - save manifest with invalid base64
func TestVerifySaveManifestInvalidBase64(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "manifest.bin")

	manifestEnvelopeB64 := "!!!invalid-base64!!!"
	pubKeyBytes, _ := create130BytePublicKey(t)
	validKey260 := hex.EncodeToString(pubKeyBytes)
	appAttJSON := fmt.Sprintf(`{"message":"deadbeef","publicKey":"%s","signature":"%s"}`, validKey260, strings.Repeat("ab", 64))

	apiResponse := &api.SignablePayloadResponse{
		SignablePayload:        "test-payload",
		QosManifestEnvelopeB64: manifestEnvelopeB64,
		Attestations: map[api.AttestationType]string{
			api.AppAttestationKey:  appAttJSON,
			api.BootAttestationKey: "boot-doc",
		},
	}

	mockAPI := &mockAPIClient{response: apiResponse}
	mockVerifier := &mockAttestationVerifier{}

	service := NewService(mockAPI, mockVerifier)

	req := &VerifyRequest{
		UnsignedPayload:  "unsigned-payload",
		SaveManifestPath: manifestPath,
	}

	result, err := service.Verify(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "failed to decode manifest envelope")

	// Manifest should not be saved if decode fails
	_, err = os.Stat(manifestPath)
	require.True(t, os.IsNotExist(err))
}

// Test processManifest
func TestProcessManifest(t *testing.T) {
	service := NewService(&mockAPIClient{}, &mockAttestationVerifier{})

	t.Run("empty manifest b64", func(t *testing.T) {
		response := &api.SignablePayloadResponse{
			QosManifestB64: "",
		}
		result := &VerifyResult{}

		err := service.processManifest(response, []byte{}, result)
		require.NoError(t, err) // Empty manifest should be skipped gracefully
	})

	t.Run("invalid manifest b64", func(t *testing.T) {
		response := &api.SignablePayloadResponse{
			QosManifestB64:  "!!!invalid!!!",
			ManifestVersion: manifest.V2,
		}
		result := &VerifyResult{}

		err := service.processManifest(response, []byte{}, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to decode QoS manifest")
	})

	t.Run("invalid raw manifest data", func(t *testing.T) {
		invalidB64 := base64.StdEncoding.EncodeToString([]byte{0xFF})
		response := &api.SignablePayloadResponse{
			QosManifestB64:  invalidB64,
			ManifestVersion: manifest.V2,
		}
		result := &VerifyResult{}

		err := service.processManifest(response, []byte{}, result)
		require.Error(t, err)
	})

	t.Run("manifest envelope with invalid data", func(t *testing.T) {
		invalidEnvB64 := base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFE})
		invalidRawB64 := base64.StdEncoding.EncodeToString([]byte{0xEE})

		response := &api.SignablePayloadResponse{
			QosManifestB64:         invalidRawB64,
			QosManifestEnvelopeB64: invalidEnvB64,
			ManifestVersion:        manifest.V2,
		}
		result := &VerifyResult{}

		err := service.processManifest(response, []byte{}, result)
		require.Error(t, err)
	})

	t.Run("empty manifest envelope but has raw manifest", func(t *testing.T) {
		// Only raw manifest, no envelope
		invalidB64 := base64.StdEncoding.EncodeToString([]byte{0xAB})
		response := &api.SignablePayloadResponse{
			QosManifestB64:         invalidB64,
			QosManifestEnvelopeB64: "",
			ManifestVersion:        manifest.V2,
		}
		result := &VerifyResult{}

		err := service.processManifest(response, []byte{}, result)
		require.Error(t, err) // Should fail to decode invalid manifest
	})

	t.Run("real manifest from embedded testdata", func(t *testing.T) {
		manifestBytes := testdata.ManifestBin

		manifestB64 := base64.StdEncoding.EncodeToString(manifestBytes)
		manifestHash := manifest.ComputeHash(manifestBytes)
		userData, err := hex.DecodeString(manifestHash)
		require.NoError(t, err)

		response := &api.SignablePayloadResponse{
			QosManifestEnvelopeB64: manifestB64,
			ManifestVersion:        manifest.V2,
		}

		result := &VerifyResult{}

		err = service.processManifest(response, userData, result)
		require.NoError(t, err)
		require.NotNil(t, result.Manifest)
		require.True(t, result.ManifestReserialization.Matches)
		require.Equal(t, manifestHash, result.QosManifestHash)

		require.NotEmpty(t, result.Manifest.Namespace.Name)
		require.NotNil(t, result.Manifest.Pivot)

		// Additional validation: envelope hash matches since we're using envelope data
		require.Equal(t, manifestHash, result.ManifestReserialization.EnvelopeHash)
	})

	t.Run("manifest envelope from embedded testdata", func(t *testing.T) {
		// testdata/manifest.bin is an envelope
		manifestBytes := testdata.ManifestBin
		envelopeB64 := base64.StdEncoding.EncodeToString(manifestBytes)
		envelopeHash := manifest.ComputeHash(manifestBytes)
		userData, err := hex.DecodeString(envelopeHash)
		require.NoError(t, err)

		response := &api.SignablePayloadResponse{
			QosManifestEnvelopeB64: envelopeB64,
			QosManifestB64:         envelopeB64, // also set raw for fallback hash
			ManifestVersion:        manifest.V2,
		}

		result := &VerifyResult{}

		err = service.processManifest(response, userData, result)
		require.NoError(t, err)
		require.NotNil(t, result.Manifest)
		require.NotEmpty(t, result.Manifest.Namespace.Name)
	})

	t.Run("borsh unchanged", func(t *testing.T) {
		manifestBytes := testdata.ManifestBin
		envelopeB64 := base64.StdEncoding.EncodeToString(manifestBytes)
		envelopeHash := manifest.ComputeHash(manifestBytes)
		userData, err := hex.DecodeString(envelopeHash)
		require.NoError(t, err)

		response := &api.SignablePayloadResponse{
			QosManifestEnvelopeB64: envelopeB64,
			ManifestVersion:        manifest.V2,
		}
		result := &VerifyResult{}

		err = service.processManifest(response, userData, result)
		require.NoError(t, err)
		require.True(t, result.ManifestReserialization.Matches)
		require.Equal(t, envelopeHash, result.ManifestReserialization.EnvelopeHash)
	})

	t.Run("json envelope", func(t *testing.T) {
		envelopeB64 := base64.StdEncoding.EncodeToString(testdata.QosManifestEnvelopeV2JSON)
		canonicalBytes := []byte(strings.TrimSuffix(string(testdata.QosManifestEnvelopeV2CanonicalJSON), "\n"))
		manifestHash := manifest.ComputeHash(canonicalBytes)
		manifestHashBytes, err := hex.DecodeString(manifestHash)
		require.NoError(t, err)

		response := &api.SignablePayloadResponse{
			QosManifestEnvelopeB64: envelopeB64,
		}
		result := &VerifyResult{}

		err = service.processManifest(response, manifestHashBytes, result)
		require.NoError(t, err)
		require.NotNil(t, result.Manifest)
		require.True(t, result.ManifestReserialization.Matches)
		require.Equal(t, manifestHash, result.QosManifestHash)
		require.Equal(t, "synthetic-turnkey-namespace", result.Manifest.Namespace.Name)
		require.Empty(t, result.Manifest.PatchSet.Members, "JSON manifests have no patch set")
	})

	t.Run("json hash mismatch", func(t *testing.T) {
		envelopeB64 := base64.StdEncoding.EncodeToString(testdata.QosManifestEnvelopeV2JSON)
		wrongUserData := manifest.ComputeHash([]byte("not the manifest"))
		wrongUserDataBytes, err := hex.DecodeString(wrongUserData)
		require.NoError(t, err)

		response := &api.SignablePayloadResponse{
			QosManifestEnvelopeB64: envelopeB64,
		}
		result := &VerifyResult{}

		err = service.processManifest(response, wrongUserDataBytes, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "manifest hash mismatch")
		require.False(t, result.ManifestReserialization.Matches)
	})

	t.Run("json envelope decode failure is not silently retried via raw manifest fallback", func(t *testing.T) {
		// `{}` is valid JSON but fails the strict JSON manifest-envelope
		// schema (missing required fields), so the envelope is detected as
		// JSON and its decode fails. A raw manifest also being present must
		// not cause a fallback to the Borsh raw-manifest path: the JSON
		// decode error must be returned as-is, not masked or replaced by a
		// raw-manifest decode attempt/result.
		invalidJSONEnvB64 := base64.StdEncoding.EncodeToString([]byte("{}"))
		invalidRawB64 := base64.StdEncoding.EncodeToString([]byte{0xFF})

		response := &api.SignablePayloadResponse{
			QosManifestEnvelopeB64: invalidJSONEnvB64,
			QosManifestB64:         invalidRawB64,
			ManifestVersion:        manifest.V2,
		}
		result := &VerifyResult{}

		err := service.processManifest(response, []byte{}, result)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing required field")
		require.NotContains(t, err.Error(), "raw manifest decode failed",
			"a JSON-detected envelope must not fall back to the Borsh raw-manifest path")
		require.Nil(t, result.Manifest)
	})

	t.Run("json strict hash source", func(t *testing.T) {
		envelopeBytes := testdata.QosManifestEnvelopeV2JSON
		envelopeB64 := base64.StdEncoding.EncodeToString(envelopeBytes)
		envelopeHash := manifest.ComputeHash(envelopeBytes)
		envelopeHashBytes, err := hex.DecodeString(envelopeHash)
		require.NoError(t, err)

		response := &api.SignablePayloadResponse{
			QosManifestB64:         envelopeB64,
			QosManifestEnvelopeB64: envelopeB64,
		}
		result := &VerifyResult{}

		err = service.processManifest(response, envelopeHashBytes, result)
		require.Error(t, err, "a raw/envelope hash match must not satisfy the JSON hash binding")
	})

	t.Run("envelope base64 decode failure does not leak a hash of partial bytes", func(t *testing.T) {
		// base64.StdEncoding.DecodeString returns the successfully-decoded
		// prefix (a non-nil byte slice) even when it also returns a non-nil
		// error for trailing invalid characters. A valid base64 prefix
		// followed by garbage reproduces that: decoding fails, but
		// envelopeBytes is still non-nil, holding the partial prefix.
		invalidEnvelopeB64 := base64.StdEncoding.EncodeToString([]byte("hello")) + "!!!!garbage!!!!"

		rawManifestBytes, err := borsh.Serialize(manifest.Manifest{})
		require.NoError(t, err)
		rawManifestB64 := base64.StdEncoding.EncodeToString(rawManifestBytes)

		response := &api.SignablePayloadResponse{
			QosManifestEnvelopeB64: invalidEnvelopeB64,
			QosManifestB64:         rawManifestB64,
			ManifestVersion:        manifest.V2,
		}
		result := &VerifyResult{}

		// No UserData: this test only checks what EnvelopeHash gets set to
		// once the raw-manifest fallback succeeds, not the hash-matching
		// outcome.
		err = service.processManifest(response, []byte{}, result)
		require.NoError(t, err, "the raw-manifest fallback should succeed even though the envelope decode failed")
		require.Empty(t, result.ManifestReserialization.EnvelopeHash,
			"EnvelopeHash must stay empty when the envelope base64 decode failed, not a hash of the undecoded partial bytes")
	})
}

// TestCheckMetadataDigest verifies the metadataDigest assertion rules.
func TestCheckMetadataDigest(t *testing.T) {
	t.Run("no chain_metadata, empty digest: ok", func(t *testing.T) {
		require.NoError(t, checkMetadataDigest("", nil))
	})

	t.Run("no chain_metadata, digest matches empty SHA-256: ok", func(t *testing.T) {
		require.NoError(t, checkMetadataDigest(emptyMetadataDigestHex, nil))
	})

	t.Run("no chain_metadata, unexpected digest: error", func(t *testing.T) {
		err := checkMetadataDigest("aabbccdd", nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "metadataDigest mismatch")
	})

	t.Run("chain_metadata sent, matching digest: ok", func(t *testing.T) {
		networkID := "ETHEREUM_MAINNET"
		meta := &api.RequestChainMetadata{
			Ethereum: &api.EthereumChainMetadata{
				NetworkID: &networkID,
				ABIMappings: map[string]api.ABIValue{
					"0xContract": {Value: `[{"name":"transfer"}]`},
				},
			},
		}
		digest, err := meta.MetadataDigestHex()
		require.NoError(t, err)
		require.NoError(t, checkMetadataDigest(digest, meta))
	})

	t.Run("chain_metadata sent, wrong digest: error", func(t *testing.T) {
		networkID := "ETHEREUM_MAINNET"
		meta := &api.RequestChainMetadata{
			Ethereum: &api.EthereumChainMetadata{NetworkID: &networkID},
		}
		err := checkMetadataDigest("deadbeef", meta)
		require.Error(t, err)
		require.Contains(t, err.Error(), "metadataDigest mismatch")
	})

	t.Run("chain_metadata sent, empty digest: error", func(t *testing.T) {
		// When the client ships ChainMetadata, the recompute-and-compare check
		// the PR is designed to enforce must run. A missing backend digest here
		// would silently downgrade verification, so we require the digest.
		meta := &api.RequestChainMetadata{
			Ethereum: &api.EthereumChainMetadata{},
		}
		err := checkMetadataDigest("", meta)
		require.Error(t, err)
		require.Contains(t, err.Error(), "backend did not return metadataDigest")
	})
}

// TestVerifyResponse covers the post-fetch verification chain over a
// pre-fetched SignablePayloadResponse: Borsh message binding, cross-field
// public-key binding, and the nil-APIClient happy-ish path that reaches
// signature verification.
func TestVerifyResponse(t *testing.T) {
	realKeyBytes, _ := create130BytePublicKey(t)
	realKeyHex := hex.EncodeToString(realKeyBytes)
	otherKeyBytes, _ := create130BytePublicKey(t)
	otherKeyHex := hex.EncodeToString(otherKeyBytes)
	bootAttB64 := base64.StdEncoding.EncodeToString([]byte("boot-doc"))
	sigHex := strings.Repeat("ab", 64)
	goodMsg := expectedMessageHex(t, "test-payload", "", "")

	tests := []struct {
		name            string
		signablePayload string
		appMsg          string
		appPubKey       string
		docPubKey       []byte
		wantErr         string
	}{
		{
			name:            "nil APIClient reaches signature verification",
			signablePayload: "test-payload",
			appMsg:          goodMsg,
			appPubKey:       realKeyHex,
			docPubKey:       realKeyBytes,
			wantErr:         "signature verification failed",
		},
		{
			name:            "tampered signablePayload fails Borsh hash binding",
			signablePayload: "tampered-payload",
			appMsg:          goodMsg, // pinned to "test-payload"
			appPubKey:       realKeyHex,
			docPubKey:       realKeyBytes,
			wantErr:         "appAttestation.Message mismatch",
		},
		{
			name:            "appAttestation.PublicKey diverges from attestation doc",
			signablePayload: "test-payload",
			appMsg:          goodMsg,
			appPubKey:       otherKeyHex,
			docPubKey:       realKeyBytes,
			wantErr:         "appAttestation.PublicKey mismatch",
		},
		{
			name:            "malformed appAttestation.Message surfaces as decode error",
			signablePayload: "test-payload",
			appMsg:          "ZZZZZ",
			appPubKey:       realKeyHex,
			docPubKey:       realKeyBytes,
			wantErr:         "failed to decode message hex",
		},
		{
			name:            "malformed appAttestation.PublicKey surfaces as decode error",
			signablePayload: "test-payload",
			appMsg:          goodMsg,
			appPubKey:       "ZZZZ",
			docPubKey:       realKeyBytes,
			wantErr:         "failed to decode public key hex",
		},
		{
			name:            "uppercase appAttestation.Message still matches (case-insensitive binding)",
			signablePayload: "test-payload",
			appMsg:          strings.ToUpper(goodMsg),
			appPubKey:       realKeyHex,
			docPubKey:       realKeyBytes,
			wantErr:         "signature verification failed", // passes binding, fails at signature step
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			appAttJSON := fmt.Sprintf(`{"message":"%s","publicKey":"%s","signature":"%s"}`, tc.appMsg, tc.appPubKey, sigHex)
			response := &api.SignablePayloadResponse{
				SignablePayload: tc.signablePayload,
				Attestations: map[api.AttestationType]string{
					api.AppAttestationKey:  appAttJSON,
					api.BootAttestationKey: bootAttB64,
				},
			}
			service := NewService(nil, &mockAttestationVerifier{
				result: &nitroverifier.ValidationResult{
					Valid:    true,
					Document: &nitroverifier.AttestationDocument{PublicKey: tc.docPubKey},
				},
			})
			_, err := service.VerifyResponse(context.Background(), response, &VerifyResponseRequest{})
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestVerify_NilArgs guards Verify's non-nil preconditions on APIClient
// and VerifyRequest.
func TestVerify_NilArgs(t *testing.T) {
	t.Run("nil APIClient", func(t *testing.T) {
		service := NewService(nil, &mockAttestationVerifier{})
		_, err := service.Verify(context.Background(), &VerifyRequest{UnsignedPayload: "x"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "Verify requires an APIClient")
	})

	t.Run("nil VerifyRequest", func(t *testing.T) {
		service := NewService(&mockAPIClient{}, &mockAttestationVerifier{})
		_, err := service.Verify(context.Background(), nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "non-nil VerifyRequest")
	})
}

// TestVerifyResponse_NilArgs guards the two non-nil preconditions.
func TestVerifyResponse_NilArgs(t *testing.T) {
	service := NewService(nil, &mockAttestationVerifier{})

	_, err := service.VerifyResponse(context.Background(), nil, &VerifyResponseRequest{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-nil SignablePayloadResponse")

	_, err = service.VerifyResponse(context.Background(), &api.SignablePayloadResponse{}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-nil VerifyResponseRequest")
}
