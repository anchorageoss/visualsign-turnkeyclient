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
	messageHex := strings.Repeat("ff", 32)
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
	messageHex := strings.Repeat("ee", 32)
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
	appAttJSON := `{"message":"deadbeef","publicKey":"invalidkey","signature":"` + strings.Repeat("ab", 64) + `"}`

	apiResponse := &api.SignablePayloadResponse{
		SignablePayload: "test-payload",
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
		UnsignedPayload: "unsigned-payload",
	}

	result, err := service.Verify(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, result)
}

// Test Verify - invalid message hex
func TestVerifyInvalidMessageHex(t *testing.T) {
	pubKeyBytes, _ := create130BytePublicKey(t)
	validKey260 := hex.EncodeToString(pubKeyBytes)

	appAttJSON := fmt.Sprintf(`{"message":"ZZZZZ","publicKey":"%s","signature":"%s"}`, validKey260, strings.Repeat("ab", 64))

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
				ModuleID: "test-module",
				PCRs:     map[uint][]byte{},
				UserData: []byte{},
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
	require.Contains(t, err.Error(), "failed to decode message hex")
}

// Test Verify - invalid signature hex
func TestVerifyInvalidSignatureHex(t *testing.T) {
	pubKeyBytes, _ := create130BytePublicKey(t)
	validKey260 := hex.EncodeToString(pubKeyBytes)
	messageHex := strings.Repeat("de", 32)

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
				ModuleID: "test-module",
				PCRs:     map[uint][]byte{},
				UserData: []byte{},
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
}
