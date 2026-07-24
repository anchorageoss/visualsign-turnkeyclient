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
	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
)

// HTTPClient interface for dependency injection
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// KeyProvider interface for providing API keys
type KeyProvider interface {
	GetAPIKey(ctx context.Context) (*TurnkeyAPIKey, error)
}

// RequestStamper optionally authenticates an outgoing parse request by returning
// the value for the "X-Stamp" header. A nil RequestStamper uses the client's
// built-in default stamping path (which stamps only when an API key is
// configured, and sends no stamp otherwise). To send no stamp regardless of
// configuration, supply a RequestStamper whose Stamp returns an empty string.
type RequestStamper interface {
	Stamp(requestBody []byte) (string, error)
}

// turnkeyStamper adapts the existing generateStamp path to the RequestStamper
// interface so NewClient-constructed clients keep stamping with their API key.
type turnkeyStamper struct {
	client *Client
}

func (s turnkeyStamper) Stamp(requestBody []byte) (string, error) {
	return s.client.generateStamp(requestBody)
}

// Client implements the Turnkey API client
type Client struct {
	HostURI              string
	HTTPClient           HTTPClient
	APIKey               *TurnkeyAPIKey
	APIKeyProvider       KeyProvider
	VisualSignAPIVersion string
	// UseDevPath, when true, routes requests to "/visualsign-dev/api/<version>/parse"
	// instead of the canonical "/visualsign/api/<version>/parse". Use during
	// production-readiness testing of the parser deployed under the dev path.
	UseDevPath bool
	// Stamper, when non-nil, supplies the X-Stamp header for outgoing parse
	// requests. When nil, the built-in API-key stamping path is used (which
	// sends no stamp when no API key is configured, enabling unauthenticated
	// mode). NewClient wires a turnkeyStamper that reuses generateStamp.
	Stamper RequestStamper
	// AttestationField names the top-level JSON sibling field whose raw bytes
	// are copied into SignablePayloadResponse.RawAttestation. Defaults to
	// "bootProof" when empty.
	AttestationField string
}

// NewClient creates a new Turnkey API client with key provider
func NewClient(hostURI string, httpClient HTTPClient, organizationID string, provider KeyProvider) (*Client, error) {
	apiKey, err := provider.GetAPIKey(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load API key: %w", err)
	}

	apiKey.OrganizationID = organizationID

	c := &Client{
		HostURI:              hostURI,
		HTTPClient:           httpClient,
		APIKey:               apiKey,
		APIKeyProvider:       provider,
		VisualSignAPIVersion: "v2",
	}
	c.Stamper = turnkeyStamper{client: c}
	return c, nil
}

// CreateSignablePayloadRequest represents the request to create signable payload
type CreateSignablePayloadRequest struct {
	UnsignedPayload string
	Chain           string
	ChainMetadata   *RequestChainMetadata // optional — nil means no ABIs sent
}

// CreateSignablePayload calls Turnkey's visualsign API to create a signable payload
func (c *Client) CreateSignablePayload(ctx context.Context, req *CreateSignablePayloadRequest) (*SignablePayloadResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request must not be nil")
	}

	// Create the visualsign request
	reqBody := TurnkeyVisualSignRequest{}
	if c.APIKey != nil {
		reqBody.OrganizationID = c.APIKey.OrganizationID
	}
	reqBody.Request.UnsignedPayload = req.UnsignedPayload
	reqBody.Request.Chain = req.Chain
	reqBody.Request.ChainMetadata = req.ChainMetadata

	// Marshal request to JSON
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal visualsign request: %w", err)
	}

	// Default to v2 if not set (e.g., direct struct construction without NewClient)
	apiVersion := c.VisualSignAPIVersion
	if apiVersion == "" {
		apiVersion = "v2"
	}

	switch apiVersion {
	case "v1", "v2":
		// supported versions
	default:
		return nil, fmt.Errorf("unsupported visualsign API version: %q (must be \"v1\" or \"v2\")", apiVersion)
	}

	// Create and stamp the request
	pathPrefix := "/visualsign"
	if c.UseDevPath {
		pathPrefix = "/visualsign-dev"
	}
	url := fmt.Sprintf("%s%s/api/%s/parse", c.HostURI, pathPrefix, apiVersion)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Add headers
	httpReq.Header.Set("Content-Type", "application/json")

	// Generate and add stamp via the pluggable RequestStamper seam. A nil
	// stamper falls back to the built-in API-key stamping path (which returns
	// "" when no API key is configured), preserving the existing Turnkey
	// behavior for clients constructed directly rather than via NewClient.
	var stamp string
	if c.Stamper != nil {
		s, err := c.Stamper.Stamp(reqJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to generate stamp: %w", err)
		}
		stamp = s
	} else {
		s, err := c.generateStamp(reqJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to generate stamp: %w", err)
		}
		stamp = s
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

	// Capture the raw sibling attestation field (verifier-agnostic). Decode the
	// top-level envelope into a map and copy the named field's raw JSON. The
	// default field name is "bootProof" to preserve existing Turnkey behavior.
	attnField := c.AttestationField
	if attnField == "" {
		attnField = "bootProof"
	}
	var rawEnvelope map[string]json.RawMessage
	var rawAttestation json.RawMessage
	if err := json.Unmarshal(bodyBytes, &rawEnvelope); err == nil {
		rawAttestation = rawEnvelope[attnField]
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

	// Map API version string to manifest version
	mv := manifest.V2
	if apiVersion == "v1" {
		mv = manifest.V1
	}

	return &SignablePayloadResponse{
		SignablePayload:                  signablePayloadString,
		ParsedPayload:                    turnkeyResp.Response.ParsedTransaction.Payload.ParsedPayload,
		InputPayloadDigest:               turnkeyResp.Response.ParsedTransaction.Payload.InputPayloadDigest,
		MetadataDigest:                   turnkeyResp.Response.ParsedTransaction.Payload.MetadataDigest,
		TurnkeySerializedSignablePayload: signablePayloadString,
		ManifestVersion:                  mv,
		Attestations:                     attestations,
		QosManifestB64:                   qosManifestB64,
		QosManifestEnvelopeB64:           qosManifestEnvelopeB64,
		EphemeralPublicKeyHex:            ephemeralPublicKeyHex,
		EnclaveApp:                       enclaveApp,
		DeploymentLabel:                  deploymentLabel,
		RawAttestation:                   rawAttestation,
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
