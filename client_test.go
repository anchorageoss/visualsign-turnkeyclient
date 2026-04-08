package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/api"
	"github.com/anchorageoss/visualsign-turnkeyclient/keys"
	"github.com/stretchr/testify/require"
)

// TestNewTurnkeyClient tests creating a new Turnkey client
func TestNewTurnkeyClient(t *testing.T) {
	// Create a mock API key provider
	mockProvider := &MockAPIKeyProvider{
		apiKey: &api.TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     createTestPrivateKey(t),
			OrganizationID: "test-org",
		},
	}

	httpClient := &http.Client{}
	client, err := api.NewClient("https://api.turnkey.com", httpClient, "org-123", mockProvider)

	require.NoError(t, err)
	require.NotNil(t, client)
	require.Equal(t, "https://api.turnkey.com", client.HostURI)
	require.Equal(t, "org-123", client.APIKey.OrganizationID)
}

// TestNewTurnkeyClientFailsWithBadProvider tests error handling with bad provider
func TestNewTurnkeyClientFailsWithBadProvider(t *testing.T) {
	// Create a provider that returns an error
	mockProvider := &MockAPIKeyProvider{
		err: "test error",
	}

	httpClient := &http.Client{}
	client, err := api.NewClient("https://api.turnkey.com", httpClient, "org-123", mockProvider)

	require.Error(t, err)
	require.Nil(t, client)
	require.Contains(t, err.Error(), "failed to load API key")
}

// TestGenerateStamp tests stamp generation
func TestGenerateStamp(t *testing.T) {
	// Skip this test - generateStamp is now private, tested via CreateSignablePayload
	t.Skip("private method")
}

// TestCreateSignablePayloadSuccess tests successful payload creation
func TestCreateSignablePayloadSuccess(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request headers
		require.NotEmpty(t, r.Header.Get("X-Stamp"))

		// Return mock response
		response := api.TurnkeyVisualSignResponse{
			Response: struct {
				ParsedTransaction struct {
					Payload struct {
						SignablePayload    string `json:"signablePayload"`
						ParsedPayload      string `json:"parsedPayload,omitempty"`
						InputPayloadDigest string `json:"inputPayloadDigest,omitempty"`
						MetadataDigest     string `json:"metadataDigest,omitempty"`
					} `json:"payload"`
					Signature *api.TurnkeySignature `json:"signature,omitempty"`
				} `json:"parsedTransaction"`
			}{},
		}

		response.Response.ParsedTransaction.Payload.SignablePayload = "test-payload"
		response.Response.ParsedTransaction.Signature = &api.TurnkeySignature{
			Message:   "message-hex",
			PublicKey: "pubkey-hex",
			Scheme:    "SIGNATURE_SCHEME_TK_API_P256",
			Signature: "sig-hex",
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	privKey := createTestPrivateKey(t)
	client := &api.Client{
		HostURI:    server.URL,
		HTTPClient: &http.Client{},
		APIKey: &api.TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	response, err := client.CreateSignablePayload(context.Background(), &api.CreateSignablePayloadRequest{
		UnsignedPayload: "unsigned-payload",
		Chain:           "CHAIN_SOLANA",
	})

	require.NoError(t, err)
	require.Equal(t, "test-payload", response.SignablePayload)
}

// TestCreateSignablePayloadNetworkError tests handling of network errors
func TestCreateSignablePayloadNetworkError(t *testing.T) {
	privKey := createTestPrivateKey(t)
	client := &api.Client{
		HostURI:    "https://invalid-host-that-does-not-exist.com",
		HTTPClient: &http.Client{},
		APIKey: &api.TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	response, err := client.CreateSignablePayload(context.Background(), &api.CreateSignablePayloadRequest{
		UnsignedPayload: "unsigned-payload",
		Chain:           "CHAIN_SOLANA",
	})

	require.Error(t, err)
	require.Nil(t, response)
}

// TestCreateSignablePayloadBadStatus tests handling of bad HTTP status
func TestCreateSignablePayloadBadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad request"}`))
	}))
	defer server.Close()

	privKey := createTestPrivateKey(t)
	client := &api.Client{
		HostURI:    server.URL,
		HTTPClient: &http.Client{},
		APIKey: &api.TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	response, err := client.CreateSignablePayload(context.Background(), &api.CreateSignablePayloadRequest{
		UnsignedPayload: "unsigned-payload",
		Chain:           "CHAIN_SOLANA",
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "non-OK status")
	require.Nil(t, response)
}

// TestTurnkeyStampSerialization tests stamp JSON serialization
func TestTurnkeyStampSerialization(t *testing.T) {
	stamp := api.TurnkeyStamp{
		PublicKey: "test-public-key",
		Signature: "test-signature",
		Scheme:    "SIGNATURE_SCHEME_TK_API_P256",
	}

	data, err := json.Marshal(stamp)
	require.NoError(t, err)

	// Should be valid JSON
	var decoded api.TurnkeyStamp
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	require.Equal(t, stamp.PublicKey, decoded.PublicKey)
	require.Equal(t, stamp.Signature, decoded.Signature)
	require.Equal(t, stamp.Scheme, decoded.Scheme)
}

// TestTurnkeyVisualSignRequestSerialization tests request serialization
func TestTurnkeyVisualSignRequestSerialization(t *testing.T) {
	req := api.TurnkeyVisualSignRequest{
		OrganizationID: "org-123",
	}
	req.Request.UnsignedPayload = "payload"
	req.Request.Chain = "CHAIN_SOLANA"

	data, err := json.Marshal(req)
	require.NoError(t, err)

	// Should be valid JSON
	var decoded api.TurnkeyVisualSignRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	require.Equal(t, "org-123", decoded.OrganizationID)
	require.Equal(t, "payload", decoded.Request.UnsignedPayload)
	require.Equal(t, "CHAIN_SOLANA", decoded.Request.Chain)
}

// MockAPIKeyProvider provides a mock implementation of APIKeyProvider
type MockAPIKeyProvider struct {
	apiKey *api.TurnkeyAPIKey
	err    string
}

func (m *MockAPIKeyProvider) GetAPIKey(ctx context.Context) (*api.TurnkeyAPIKey, error) {
	if m.err != "" {
		return nil, &mockError{msg: m.err}
	}
	return m.apiKey, nil
}

type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}

// createTestPrivateKey creates a test ECDSA private key
func createTestPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return privKey
}

// TestGetBootAttestation tests boot attestation retrieval with default enclave type
func TestGetBootAttestation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := api.AttestationQueryResponse{
			AttestationDocument: "test-attestation-doc",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	privKey := createTestPrivateKey(t)
	client := &api.Client{
		HostURI:    server.URL,
		HTTPClient: &http.Client{},
		APIKey: &api.TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	attestation, err := client.GetBootAttestation(context.Background(), "pubkey-123", "")

	require.NoError(t, err)
	require.Equal(t, "test-attestation-doc", attestation)
}

// TestGetBootAttestationWithCustomEnclaveType tests boot attestation retrieval with custom enclave type
func TestGetBootAttestationWithCustomEnclaveType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := api.AttestationQueryResponse{
			AttestationDocument: "test-attestation-doc-custom",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	privKey := createTestPrivateKey(t)
	client := &api.Client{
		HostURI:    server.URL,
		HTTPClient: &http.Client{},
		APIKey: &api.TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	attestation, err := client.GetBootAttestation(context.Background(), "pubkey-123", "custom-enclave")

	require.NoError(t, err)
	require.Equal(t, "test-attestation-doc-custom", attestation)
}

// TestFileAPIKeyProviderGetAPIKey tests file-based key provider
func TestFileAPIKeyProviderGetAPIKey(t *testing.T) {
	// Generate a test key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tempDir := t.TempDir()
	keyName := "provider-key"

	// Create config directory
	configDir := tempDir + "/.config/turnkey/keys"
	err = os.MkdirAll(configDir, 0o755)
	require.NoError(t, err)

	// Create public key file
	publicKeyPath := configDir + "/" + keyName + ".public"
	err = os.WriteFile(publicKeyPath, []byte("cafebabe"), 0o644)
	require.NoError(t, err)

	// Create private key file
	d := privKey.D.Bytes()
	dPadded := make([]byte, 32)
	copy(dPadded[32-len(d):], d)
	privateKeyHex := hex.EncodeToString(dPadded)
	privateKeyContent := privateKeyHex + ":p256"
	privateKeyPath := configDir + "/" + keyName + ".private"
	err = os.WriteFile(privateKeyPath, []byte(privateKeyContent), 0o644)
	require.NoError(t, err)

	// Override home directory
	t.Setenv("HOME", tempDir)

	provider := &keys.FileKeyProvider{KeyName: keyName}
	apiKey, err := provider.GetAPIKey(context.Background())

	require.NoError(t, err)
	require.NotNil(t, apiKey)
}

// BenchmarkGenerateStamp benchmarks stamp generation via CreateSignablePayload
func BenchmarkGenerateStamp(b *testing.B) {
	// Benchmarks for private methods should be in api_test.go within the api package
	b.Skip("private method - see api_test.go")
}

// BenchmarkSignWithAPIKey benchmarks API key signing
func BenchmarkSignWithAPIKey(b *testing.B) {
	// Benchmarks for private methods should be in api_test.go within the api package
	b.Skip("private method - see api_test.go")
}
