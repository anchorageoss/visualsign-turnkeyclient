package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeStamper returns a fixed stamp value for testing.
type fakeStamper struct {
	stamp string
	err   error
}

func (f *fakeStamper) Stamp(requestBody []byte) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.stamp, nil
}

// recordingHandler captures the incoming request headers and body.
type recordingHandler struct {
	headers http.Header
	body    []byte
	resp    []byte
}

func (h *recordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.headers = r.Header.Clone()
	h.body, _ = io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(h.resp)
}

// TestCreateSignablePayload_NilStamper_Unauthenticated verifies that a Client
// with no RequestStamper (and no APIKey) can still successfully parse a
// payload against an unauthenticated endpoint, sending no X-Stamp header.
func TestCreateSignablePayload_NilStamper_Unauthenticated(t *testing.T) {
	resp := TurnkeyVisualSignResponse{}
	resp.Response.ParsedTransaction.Payload.SignablePayload = "ok"
	resp.Response.ParsedTransaction.Payload.InputPayloadDigest = "deadbeef"
	respBody, _ := json.Marshal(resp)

	handler := &recordingHandler{resp: respBody}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := &Client{
		HostURI:              srv.URL,
		HTTPClient:           http.DefaultClient,
		Stamper:              nil,
		VisualSignAPIVersion: "v2",
	}

	result, err := client.CreateSignablePayload(context.Background(), &CreateSignablePayloadRequest{
		UnsignedPayload: "my-payload",
		Chain:           "CHAIN_ETHEREUM",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "ok", result.SignablePayload)

	// No stamp header should be sent.
	_, hasStamp := handler.headers["X-Stamp"]
	require.False(t, hasStamp, "expected no X-Stamp header for nil stamper")

	// The request body must carry the unsigned_payload under request.
	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(handler.body, &body))
	reqField, ok := body["request"]
	require.True(t, ok, "expected 'request' field in body")
	var req struct {
		UnsignedPayload string `json:"unsigned_payload"`
	}
	require.NoError(t, json.Unmarshal(reqField, &req))
	require.Equal(t, "my-payload", req.UnsignedPayload)

	// With no API key there is no organization, so the field is omitted.
	_, hasOrg := body["organization_id"]
	require.False(t, hasOrg, "expected no organization_id field without an API key")
}

// TestCreateSignablePayload_CustomStamper verifies that a non-nil RequestStamper
// supplies the X-Stamp header value verbatim.
func TestCreateSignablePayload_CustomStamper(t *testing.T) {
	resp := TurnkeyVisualSignResponse{}
	resp.Response.ParsedTransaction.Payload.SignablePayload = "ok"
	respBody, _ := json.Marshal(resp)

	handler := &recordingHandler{resp: respBody}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := &Client{
		HostURI:              srv.URL,
		HTTPClient:           http.DefaultClient,
		Stamper:              &fakeStamper{stamp: "abc"},
		VisualSignAPIVersion: "v2",
	}

	result, err := client.CreateSignablePayload(context.Background(), &CreateSignablePayloadRequest{
		UnsignedPayload: "p",
		Chain:           "CHAIN_ETHEREUM",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	require.Equal(t, "abc", handler.headers.Get("X-Stamp"))
}

// failingBody is a response body whose Read always fails.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (failingBody) Close() error             { return nil }

// failingBodyClient returns a 200 response whose body cannot be read.
type failingBodyClient struct{}

func (failingBodyClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: failingBody{}, Header: http.Header{}}, nil
}

// TestCreateSignablePayload_ResponseReadError verifies that a failure reading
// the response body is reported as such rather than as a decode error.
func TestCreateSignablePayload_ResponseReadError(t *testing.T) {
	client := &Client{
		HostURI:              "http://example.invalid",
		HTTPClient:           failingBodyClient{},
		VisualSignAPIVersion: "v2",
	}

	_, err := client.CreateSignablePayload(context.Background(), &CreateSignablePayloadRequest{
		UnsignedPayload: "p",
		Chain:           "CHAIN_ETHEREUM",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to read response")
	require.Contains(t, err.Error(), "connection reset")
}

// newStampTestServer returns a recording server that answers parse requests
// with a minimal successful response.
func newStampTestServer(t *testing.T) (*recordingHandler, *httptest.Server) {
	t.Helper()
	resp := TurnkeyVisualSignResponse{}
	resp.Response.ParsedTransaction.Payload.SignablePayload = "ok"
	respBody, err := json.Marshal(resp)
	require.NoError(t, err)
	handler := &recordingHandler{resp: respBody}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return handler, srv
}

func newStampTestKey(t *testing.T, publicKey string) *TurnkeyAPIKey {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &TurnkeyAPIKey{PublicKey: publicKey, PrivateKey: privKey}
}

// TestCreateSignablePayload_CopiedClientReplacedKey verifies that the default
// stamper wired by NewClient signs with the key of the client making the call,
// not the client originally passed to NewClient.
func TestCreateSignablePayload_CopiedClientReplacedKey(t *testing.T) {
	handler, srv := newStampTestServer(t)

	original, err := NewClient(srv.URL, http.DefaultClient, "org-original",
		&mockKeyProvider{apiKey: newStampTestKey(t, "original-public-key")})
	require.NoError(t, err)

	copied := *original
	replacement := newStampTestKey(t, "replacement-public-key")
	replacement.OrganizationID = "org-replacement"
	copied.APIKey = replacement

	_, err = copied.CreateSignablePayload(context.Background(), &CreateSignablePayloadRequest{
		UnsignedPayload: "p",
		Chain:           "CHAIN_ETHEREUM",
	})
	require.NoError(t, err)

	stampRaw, err := base64.RawURLEncoding.DecodeString(handler.headers.Get("X-Stamp"))
	require.NoError(t, err)
	var stamp TurnkeyStamp
	require.NoError(t, json.Unmarshal(stampRaw, &stamp))
	require.Equal(t, "replacement-public-key", stamp.PublicKey)

	// The signature must verify against the replacement key over the body sent.
	sig, err := hex.DecodeString(stamp.Signature)
	require.NoError(t, err)
	digest := sha256.Sum256(handler.body)
	require.True(t, ecdsa.VerifyASN1(&replacement.PrivateKey.PublicKey, digest[:], sig),
		"stamp signature must verify with the copy's key")

	var body struct {
		OrganizationID string `json:"organization_id"`
	}
	require.NoError(t, json.Unmarshal(handler.body, &body))
	require.Equal(t, "org-replacement", body.OrganizationID)
}

// TestCreateSignablePayload_CopiedClientClearedKey verifies that clearing the
// API key on a copy of a NewClient-constructed client disables stamping.
func TestCreateSignablePayload_CopiedClientClearedKey(t *testing.T) {
	handler, srv := newStampTestServer(t)

	original, err := NewClient(srv.URL, http.DefaultClient, "org-original",
		&mockKeyProvider{apiKey: newStampTestKey(t, "original-public-key")})
	require.NoError(t, err)

	copied := *original
	copied.APIKey = nil

	_, err = copied.CreateSignablePayload(context.Background(), &CreateSignablePayloadRequest{
		UnsignedPayload: "p",
		Chain:           "CHAIN_ETHEREUM",
	})
	require.NoError(t, err)

	_, hasStamp := handler.headers["X-Stamp"]
	require.False(t, hasStamp, "expected no X-Stamp header after clearing the copy's API key")
}
