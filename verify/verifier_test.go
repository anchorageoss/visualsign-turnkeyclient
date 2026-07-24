package verify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/api"
	"github.com/stretchr/testify/require"
)

// recordingVerifier is a fake Verifier that captures the response it receives
// and returns a canned VerifierResult.
type recordingVerifier struct {
	got  *api.SignablePayloadResponse
	resp *VerifierResult
	err  error
}

func (r *recordingVerifier) Verify(ctx context.Context, resp *api.SignablePayloadResponse) (*VerifierResult, error) {
	r.got = resp
	return r.resp, r.err
}

// TestRunVerify verifies that RunVerify calls the parse client, hands the
// parsed response to the Verifier, and returns the verifier's result together
// with the parsed response.
func TestRunVerify(t *testing.T) {
	canned := `{"response":{"parsedTransaction":{"payload":{"signablePayload":"s","parsedPayload":"p","inputPayloadDigest":"ipd","metadataDigest":"mdd"}}}}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(canned))
	}))
	defer srv.Close()

	client := &api.Client{
		HostURI:              srv.URL,
		HTTPClient:           http.DefaultClient,
		Stamper:              nil,
		VisualSignAPIVersion: "v2",
	}

	wantResult := &VerifierResult{OK: true, Detail: "all good", Signed: map[string]string{"a": "b"}}
	verifier := &recordingVerifier{resp: wantResult}

	resp, result, err := RunVerify(context.Background(), client, &api.CreateSignablePayloadRequest{
		UnsignedPayload: "p",
		Chain:           "CHAIN_ETHEREUM",
	}, verifier)

	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "s", resp.SignablePayload)
	require.Equal(t, "ipd", resp.InputPayloadDigest)
	require.Equal(t, "mdd", resp.MetadataDigest)

	// The verifier received the parsed response.
	require.NotNil(t, verifier.got)
	require.Equal(t, "ipd", verifier.got.InputPayloadDigest)

	// RunVerify returned the verifier's result verbatim.
	require.Equal(t, wantResult, result)
}

// TestRunVerify_ClientError verifies that an API error is surfaced and the
// verifier is not invoked.
func TestRunVerify_ClientError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	client := &api.Client{
		HostURI:              srv.URL,
		HTTPClient:           http.DefaultClient,
		VisualSignAPIVersion: "v2",
	}

	verifier := &recordingVerifier{}
	resp, result, err := RunVerify(context.Background(), client, &api.CreateSignablePayloadRequest{
		UnsignedPayload: "p",
		Chain:           "CHAIN_ETHEREUM",
	}, verifier)

	require.Error(t, err)
	require.Nil(t, resp)
	require.Nil(t, result)
	require.Nil(t, verifier.got, "verifier must not be called on client error")
}

// TestVerifierResult_JSON confirms VerifierResult serializes with the expected
// field names.
func TestVerifierResult_JSON(t *testing.T) {
	r := &VerifierResult{OK: true, Detail: "d", Signed: map[string]string{"k": "v"}}
	b, err := json.Marshal(r)
	require.NoError(t, err)
	require.JSONEq(t, `{"ok":true,"detail":"d","signed":{"k":"v"}}`, string(b))
}
