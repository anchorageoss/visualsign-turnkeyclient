package api

import (
	"context"
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
