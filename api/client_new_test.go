package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Mock implementations for testing

type mockHTTPClient struct {
	response    *http.Response
	err         error
	lastRequest *http.Request
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.lastRequest = req
	return m.response, m.err
}

type mockKeyProvider struct {
	apiKey *TurnkeyAPIKey
	err    error
}

func (m *mockKeyProvider) GetAPIKey(ctx context.Context) (*TurnkeyAPIKey, error) {
	return m.apiKey, m.err
}

// TestNewClient tests the NewClient function
func TestNewClient(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	apiKey := &TurnkeyAPIKey{
		PublicKey:  "test-public-key",
		PrivateKey: privKey,
	}

	t.Run("successful client creation", func(t *testing.T) {
		provider := &mockKeyProvider{apiKey: apiKey}
		httpClient := &http.Client{}

		client, err := NewClient("https://api.turnkey.com", httpClient, "test-org", provider)
		require.NoError(t, err)
		require.NotNil(t, client)
		require.Equal(t, "https://api.turnkey.com", client.HostURI)
		require.Equal(t, "test-org", client.APIKey.OrganizationID)
		require.Equal(t, apiKey.PublicKey, client.APIKey.PublicKey)
	})

	t.Run("provider returns error", func(t *testing.T) {
		provider := &mockKeyProvider{err: fmt.Errorf("key not found")}
		httpClient := &http.Client{}

		client, err := NewClient("https://api.turnkey.com", httpClient, "test-org", provider)
		require.Error(t, err)
		require.Nil(t, client)
		require.Contains(t, err.Error(), "failed to load API key")
	})
}

// TestCreateSignablePayload tests the CreateSignablePayload function
func TestCreateSignablePayload(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		HostURI: "https://api.turnkey.com",
		APIKey: &TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	t.Run("successful response", func(t *testing.T) {
		response := TurnkeyVisualSignResponse{}
		response.Response.ParsedTransaction.Payload.SignablePayload = "test-signable-payload"

		responseBody, _ := json.Marshal(response)
		mockResp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(responseBody)),
		}

		mockClient := &mockHTTPClient{response: mockResp}
		client.HTTPClient = mockClient

		req := &CreateSignablePayloadRequest{
			UnsignedPayload: "test-payload",
			Chain:           "test-chain",
		}

		result, err := client.CreateSignablePayload(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, "test-signable-payload", result.SignablePayload)
	})

	t.Run("network error", func(t *testing.T) {
		mockClient := &mockHTTPClient{err: fmt.Errorf("network error")}
		client.HTTPClient = mockClient

		req := &CreateSignablePayloadRequest{
			UnsignedPayload: "test-payload",
			Chain:           "test-chain",
		}

		result, err := client.CreateSignablePayload(context.Background(), req)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "failed to send request")
	})

	t.Run("non-200 status code", func(t *testing.T) {
		mockResp := &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(strings.NewReader("bad request")),
		}

		mockClient := &mockHTTPClient{response: mockResp}
		client.HTTPClient = mockClient

		req := &CreateSignablePayloadRequest{
			UnsignedPayload: "test-payload",
			Chain:           "test-chain",
		}

		result, err := client.CreateSignablePayload(context.Background(), req)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "non-OK status")
	})

	t.Run("invalid JSON response", func(t *testing.T) {
		mockResp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("not json")),
		}

		mockClient := &mockHTTPClient{response: mockResp}
		client.HTTPClient = mockClient

		req := &CreateSignablePayloadRequest{
			UnsignedPayload: "test-payload",
			Chain:           "test-chain",
		}

		result, err := client.CreateSignablePayload(context.Background(), req)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "failed to decode response")
	})

	t.Run("response with error field", func(t *testing.T) {
		response := TurnkeyVisualSignResponse{
			Error: "API error occurred",
		}

		responseBody, _ := json.Marshal(response)
		mockResp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(responseBody)),
		}

		mockClient := &mockHTTPClient{response: mockResp}
		client.HTTPClient = mockClient

		req := &CreateSignablePayloadRequest{
			UnsignedPayload: "test-payload",
			Chain:           "test-chain",
		}

		result, err := client.CreateSignablePayload(context.Background(), req)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "API error occurred")
	})

	t.Run("nil APIKey returns error", func(t *testing.T) {
		nilAPIKeyClient := &Client{
			HostURI:    "https://api.turnkey.com",
			HTTPClient: &mockHTTPClient{},
		}

		req := &CreateSignablePayloadRequest{
			UnsignedPayload: "test-payload",
			Chain:           "test-chain",
		}

		result, err := nilAPIKeyClient.CreateSignablePayload(context.Background(), req)
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "APIKey must be configured")
	})

	t.Run("nil private key skips stamp", func(t *testing.T) {
		response := TurnkeyVisualSignResponse{}
		response.Response.ParsedTransaction.Payload.SignablePayload = "test-signable-payload"

		responseBody, _ := json.Marshal(response)
		mockResp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(responseBody)),
		}

		mockClient := &mockHTTPClient{response: mockResp}
		nilKeyClient := &Client{
			HostURI:    "https://api.turnkey.com",
			HTTPClient: mockClient,
			APIKey: &TurnkeyAPIKey{
				PublicKey:      "test-public-key",
				OrganizationID: "test-org",
			},
		}

		req := &CreateSignablePayloadRequest{
			UnsignedPayload: "test-payload",
			Chain:           "test-chain",
		}

		result, err := nilKeyClient.CreateSignablePayload(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, "test-signable-payload", result.SignablePayload)
		_, ok := mockClient.lastRequest.Header["X-Stamp"]
		require.False(t, ok)
	})

	t.Run("response with attestations", func(t *testing.T) {
		response := TurnkeyVisualSignResponse{
			BootProof: &TurnkeyBootProof{
				AwsAttestationDocB64:   "test-attestation",
				QosManifestB64:         "test-manifest",
				QosManifestEnvelopeB64: "test-envelope",
			},
		}
		response.Response.ParsedTransaction.Payload.SignablePayload = "test-payload"

		// Set signature data
		response.Response.ParsedTransaction.Signature = &TurnkeySignature{
			Message:   "test-message",
			PublicKey: "test-key",
			Scheme:    "test-scheme",
			Signature: "test-sig",
		}

		responseBody, _ := json.Marshal(response)
		mockResp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(responseBody)),
		}

		mockClient := &mockHTTPClient{response: mockResp}
		client.HTTPClient = mockClient

		req := &CreateSignablePayloadRequest{
			UnsignedPayload: "test-payload",
			Chain:           "test-chain",
		}

		result, err := client.CreateSignablePayload(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, "test-payload", result.SignablePayload)
		require.Equal(t, "test-attestation", result.Attestations[BootAttestationKey])
		require.NotEmpty(t, result.Attestations[AppAttestationKey])
		require.Equal(t, "test-manifest", result.QosManifestB64)
		require.Equal(t, "test-envelope", result.QosManifestEnvelopeB64)
	})
}

// TestGetBootAttestation tests the GetBootAttestation function
func TestGetBootAttestation(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		HostURI: "https://api.turnkey.com",
		APIKey: &TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	t.Run("successful response", func(t *testing.T) {
		response := AttestationQueryResponse{
			AttestationDocument: "test-attestation-doc",
		}

		responseBody, _ := json.Marshal(response)
		mockResp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(responseBody)),
		}

		mockClient := &mockHTTPClient{response: mockResp}
		client.HTTPClient = mockClient

		result, err := client.GetBootAttestation(context.Background(), "test-key", "signer")
		require.NoError(t, err)
		require.Equal(t, "test-attestation-doc", result)
	})

	t.Run("default enclave type", func(t *testing.T) {
		response := AttestationQueryResponse{
			AttestationDocument: "test-attestation-doc",
		}

		responseBody, _ := json.Marshal(response)
		mockResp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(responseBody)),
		}

		mockClient := &mockHTTPClient{response: mockResp}
		client.HTTPClient = mockClient

		result, err := client.GetBootAttestation(context.Background(), "test-key", "")
		require.NoError(t, err)
		require.Equal(t, "test-attestation-doc", result)
	})

	t.Run("nil APIKey returns error", func(t *testing.T) {
		nilAPIKeyClient := &Client{
			HostURI:    "https://api.turnkey.com",
			HTTPClient: &mockHTTPClient{},
		}

		result, err := nilAPIKeyClient.GetBootAttestation(context.Background(), "test-key", "signer")
		require.Error(t, err)
		require.Empty(t, result)
		require.Contains(t, err.Error(), "APIKey must be configured")
	})

	t.Run("nil private key skips stamp", func(t *testing.T) {
		response := AttestationQueryResponse{
			AttestationDocument: "test-attestation-doc",
		}

		responseBody, _ := json.Marshal(response)
		mockResp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(responseBody)),
		}

		mockClient := &mockHTTPClient{response: mockResp}
		nilKeyClient := &Client{
			HostURI:    "https://api.turnkey.com",
			HTTPClient: mockClient,
			APIKey: &TurnkeyAPIKey{
				PublicKey:      "test-public-key",
				OrganizationID: "test-org",
			},
		}

		result, err := nilKeyClient.GetBootAttestation(context.Background(), "test-key", "signer")
		require.NoError(t, err)
		require.Equal(t, "test-attestation-doc", result)
		_, ok := mockClient.lastRequest.Header["X-Stamp"]
		require.False(t, ok)
	})

	t.Run("network error", func(t *testing.T) {
		mockClient := &mockHTTPClient{err: fmt.Errorf("network error")}
		client.HTTPClient = mockClient

		result, err := client.GetBootAttestation(context.Background(), "test-key", "signer")
		require.Error(t, err)
		require.Empty(t, result)
		require.Contains(t, err.Error(), "failed to send request")
	})

	t.Run("non-200 status", func(t *testing.T) {
		mockResp := &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(strings.NewReader("not found")),
		}

		mockClient := &mockHTTPClient{response: mockResp}
		client.HTTPClient = mockClient

		result, err := client.GetBootAttestation(context.Background(), "test-key", "signer")
		require.Error(t, err)
		require.Empty(t, result)
		require.Contains(t, err.Error(), "non-OK status")
	})

	t.Run("invalid JSON response", func(t *testing.T) {
		mockResp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("not json")),
		}

		mockClient := &mockHTTPClient{response: mockResp}
		client.HTTPClient = mockClient

		result, err := client.GetBootAttestation(context.Background(), "test-key", "signer")
		require.Error(t, err)
		require.Empty(t, result)
		require.Contains(t, err.Error(), "failed to decode")
	})
}
