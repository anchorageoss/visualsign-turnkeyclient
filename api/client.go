package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/anchorageoss/visualsign-turnkeyclient/crypto"
)

// HTTPClient interface for dependency injection
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// KeyProvider interface for providing API keys
type KeyProvider interface {
	GetAPIKey(ctx context.Context) (*TurnkeyAPIKey, error)
}

// Client implements the Turnkey API client
type Client struct {
	HostURI        string
	HTTPClient     HTTPClient
	APIKey         *TurnkeyAPIKey
	APIKeyProvider KeyProvider
}

// NewClient creates a new Turnkey API client with key provider
func NewClient(hostURI string, httpClient HTTPClient, organizationID string, provider KeyProvider) (*Client, error) {
	apiKey, err := provider.GetAPIKey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load API key: %w", err)
	}

	apiKey.OrganizationID = organizationID

	return &Client{
		HostURI:        hostURI,
		HTTPClient:     httpClient,
		APIKey:         apiKey,
		APIKeyProvider: provider,
	}, nil
}

// CreateSignablePayloadRequest represents the request to create signable payload
type CreateSignablePayloadRequest struct {
	UnsignedPayload string
	Chain           string
}

// CreateSignablePayload calls Turnkey's visualsign API to create a signable payload
func (c *Client) CreateSignablePayload(ctx context.Context, req *CreateSignablePayloadRequest) (*SignablePayloadResponse, error) {
	if c.APIKey == nil {
		return nil, fmt.Errorf("APIKey must be configured to create a signable payload")
	}

	if req == nil {
		return nil, fmt.Errorf("request must not be nil")
	}

	// Create the visualsign request
	reqBody := TurnkeyVisualSignRequest{
		Request: struct {
			UnsignedPayload string `json:"unsigned_payload"`
			Chain           string `json:"chain"`
		}{
			UnsignedPayload: req.UnsignedPayload,
			Chain:           req.Chain,
		},
		OrganizationID: c.APIKey.OrganizationID,
	}

	// Marshal request to JSON
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal visualsign request: %w", err)
	}

	// Create and stamp the request
	url := fmt.Sprintf("%s/visualsign/api/v1/parse", c.HostURI)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Add headers
	httpReq.Header.Set("Content-Type", "application/json")

	// Generate and add stamp
	stamp, err := c.generateStamp(reqJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to generate stamp: %w", err)
	}
	if stamp != "" {
		httpReq.Header.Set("X-Stamp", stamp)
	}

	// Send request
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to Turnkey visualsign API: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("turnkey API returned non-OK status: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var turnkeyResp TurnkeyVisualSignResponse
	bodyBytes, _ := io.ReadAll(resp.Body)

	err = json.Unmarshal(bodyBytes, &turnkeyResp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Check for error in response
	if turnkeyResp.Error != "" {
		return nil, fmt.Errorf("turnkey API returned error: %s", turnkeyResp.Error)
	}

	// Extract the signable payload string - keep as string, don't decode
	signablePayloadString := turnkeyResp.Response.ParsedTransaction.Payload.SignablePayload

	// Process attestations if available
	attestations := make(map[AttestationType]string)

	if turnkeyResp.Response.ParsedTransaction.Signature != nil {
		// Set app attestation from the signature response
		appAttestationData := map[string]interface{}{
			"message":   turnkeyResp.Response.ParsedTransaction.Signature.Message,
			"publicKey": turnkeyResp.Response.ParsedTransaction.Signature.PublicKey,
			"scheme":    turnkeyResp.Response.ParsedTransaction.Signature.Scheme,
			"signature": turnkeyResp.Response.ParsedTransaction.Signature.Signature,
		}
		appAttestationJSON, err := json.Marshal(appAttestationData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal app attestation: %w", err)
		}
		attestations[AppAttestationKey] = string(appAttestationJSON)
	}

	// Extract boot attestation from bootProof if available
	if turnkeyResp.BootProof != nil && turnkeyResp.BootProof.AwsAttestationDocB64 != "" {
		attestations[BootAttestationKey] = turnkeyResp.BootProof.AwsAttestationDocB64
	}

	// Extract boot proof fields if available
	var qosManifestB64, qosManifestEnvelopeB64 string
	var ephemeralPublicKeyHex, enclaveApp, deploymentLabel string
	if turnkeyResp.BootProof != nil {
		qosManifestB64 = turnkeyResp.BootProof.QosManifestB64
		qosManifestEnvelopeB64 = turnkeyResp.BootProof.QosManifestEnvelopeB64
		ephemeralPublicKeyHex = turnkeyResp.BootProof.EphemeralPublicKeyHex
		enclaveApp = turnkeyResp.BootProof.EnclaveApp
		deploymentLabel = turnkeyResp.BootProof.DeploymentLabel
	}

	return &SignablePayloadResponse{
		SignablePayload:                  signablePayloadString,
		TurnkeySerializedSignablePayload: signablePayloadString,
		Attestations:                     attestations,
		QosManifestB64:                   qosManifestB64,
		QosManifestEnvelopeB64:           qosManifestEnvelopeB64,
		EphemeralPublicKeyHex:            ephemeralPublicKeyHex,
		EnclaveApp:                       enclaveApp,
		DeploymentLabel:                  deploymentLabel,
	}, nil
}

// GetBootAttestation retrieves boot attestation for a specific public key and enclave type
func (c *Client) GetBootAttestation(ctx context.Context, publicKey, enclaveType string) (string, error) {
	if c.APIKey == nil {
		return "", fmt.Errorf("APIKey must be configured to get boot attestation")
	}

	if enclaveType == "" {
		enclaveType = "signer"
	}

	// Create the attestation query request
	reqBody := AttestationQueryRequest{
		OrganizationID: c.APIKey.OrganizationID,
		EnclaveType:    enclaveType,
		PublicKey:      publicKey,
	}

	// Marshal request to JSON
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal attestation request: %w", err)
	}

	// Create and stamp the request
	url := fmt.Sprintf("%s/public/v1/query/get_attestation", c.HostURI)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqJSON))
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Add headers
	httpReq.Header.Set("Content-Type", "application/json")

	// Generate and add stamp
	stamp, err := c.generateStamp(reqJSON)
	if err != nil {
		return "", fmt.Errorf("failed to generate stamp: %w", err)
	}
	if stamp != "" {
		httpReq.Header.Set("X-Stamp", stamp)
	}

	// Send request
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("failed to send request to attestation API: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("attestation API returned non-OK status: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var attestationResp AttestationQueryResponse
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&attestationResp); err != nil {
		return "", fmt.Errorf("failed to decode attestation response: %w", err)
	}

	return attestationResp.AttestationDocument, nil
}

// generateStamp creates an API key stamp for the request.
// Returns empty string when no API key or private key is configured (local/unauthenticated environments).
func (c *Client) generateStamp(requestBody []byte) (string, error) {
	if c.APIKey == nil || c.APIKey.PrivateKey == nil {
		return "", nil
	}

	// Sign the request body with the private key
	signature, err := c.signWithAPIKey(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to sign request body: %w", err)
	}

	// Create the stamp structure
	stamp := TurnkeyStamp{
		PublicKey: c.APIKey.PublicKey,
		Signature: hex.EncodeToString(signature),
		Scheme:    "SIGNATURE_SCHEME_TK_API_P256",
	}

	// Marshal to JSON
	stampJSON, err := json.Marshal(stamp)
	if err != nil {
		return "", fmt.Errorf("failed to marshal stamp: %w", err)
	}

	// Base64URL encode the stamp
	return base64.RawURLEncoding.EncodeToString(stampJSON), nil
}

// signWithAPIKey signs the data with the API key private key
func (c *Client) signWithAPIKey(data []byte) ([]byte, error) {
	return crypto.SignWithECDSA(c.APIKey.PrivateKey, data)
}
