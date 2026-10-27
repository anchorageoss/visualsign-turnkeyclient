package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCreateSignablePayload_RawAttestation verifies that the sibling
// attestation field named by Client.AttestationField is captured verbatim
// into SignablePayloadResponse.RawAttestation, while the standard digest
// fields remain populated.
func TestCreateSignablePayload_RawAttestation(t *testing.T) {
	canned := `{"response":{"parsedTransaction":{"payload":{"signablePayload":"s","parsedPayload":"p","inputPayloadDigest":"ipd","metadataDigest":"mdd"}}},"customAttn":{"x":1}}`

	handler := &recordingHandler{resp: []byte(canned)}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := &Client{
		HostURI:              srv.URL,
		HTTPClient:           http.DefaultClient,
		Stamper:              nil,
		VisualSignAPIVersion: "v2",
		AttestationField:     "customAttn",
	}

	result, err := client.CreateSignablePayload(context.Background(), &CreateSignablePayloadRequest{
		UnsignedPayload: "p",
		Chain:           "CHAIN_ETHEREUM",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Digests populated normally.
	require.Equal(t, "s", result.SignablePayload)
	require.Equal(t, "ipd", result.InputPayloadDigest)
	require.Equal(t, "mdd", result.MetadataDigest)

	// RawAttestation holds the raw sibling JSON.
	require.NotNil(t, result.RawAttestation)
	require.JSONEq(t, `{"x":1}`, string(result.RawAttestation))
}

// TestCreateSignablePayload_RawAttestation_DefaultBootProof verifies that the
// default attestation field name is "bootProof" when AttestationField is empty.
func TestCreateSignablePayload_RawAttestation_DefaultBootProof(t *testing.T) {
	canned := `{"response":{"parsedTransaction":{"payload":{"signablePayload":"s"}}},"bootProof":{"awsAttestationDocB64":"doc"}}`

	handler := &recordingHandler{resp: []byte(canned)}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := &Client{
		HostURI:              srv.URL,
		HTTPClient:           http.DefaultClient,
		Stamper:              nil,
		VisualSignAPIVersion: "v2",
		// AttestationField intentionally empty -> defaults to "bootProof".
	}

	result, err := client.CreateSignablePayload(context.Background(), &CreateSignablePayloadRequest{
		UnsignedPayload: "p",
		Chain:           "CHAIN_ETHEREUM",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	require.NotNil(t, result.RawAttestation)
	var bp TurnkeyBootProof
	require.NoError(t, json.Unmarshal(result.RawAttestation, &bp))
	require.Equal(t, "doc", bp.AwsAttestationDocB64)
}

// TestCreateSignablePayload_RawAttestation_Absent verifies that a missing
// sibling field yields a nil RawAttestation (no error).
func TestCreateSignablePayload_RawAttestation_Absent(t *testing.T) {
	canned := `{"response":{"parsedTransaction":{"payload":{"signablePayload":"s"}}}}`

	handler := &recordingHandler{resp: []byte(canned)}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := &Client{
		HostURI:              srv.URL,
		HTTPClient:           http.DefaultClient,
		Stamper:              nil,
		VisualSignAPIVersion: "v2",
		AttestationField:     "customAttn",
	}

	result, err := client.CreateSignablePayload(context.Background(), &CreateSignablePayloadRequest{
		UnsignedPayload: "p",
		Chain:           "CHAIN_ETHEREUM",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Nil(t, result.RawAttestation)
}

// TestCreateSignablePayload_RawAttestation_NonTurnkeyBootProof verifies that a
// bootProof not in the Turnkey shape still decodes: RawAttestation carries it
// verbatim and the legacy boot proof fields stay empty.
func TestCreateSignablePayload_RawAttestation_NonTurnkeyBootProof(t *testing.T) {
	for name, bootProof := range map[string]string{
		"string":            `"opaque"`,
		"non-string member": `{"enclaveApp":7}`,
	} {
		t.Run(name, func(t *testing.T) {
			canned := `{"response":{"parsedTransaction":{"payload":{"signablePayload":"s","inputPayloadDigest":"ipd"}}},"bootProof":` + bootProof + `}`

			handler := &recordingHandler{resp: []byte(canned)}
			srv := httptest.NewServer(handler)
			defer srv.Close()

			client := &Client{
				HostURI:              srv.URL,
				HTTPClient:           http.DefaultClient,
				VisualSignAPIVersion: "v2",
			}

			result, err := client.CreateSignablePayload(context.Background(), &CreateSignablePayloadRequest{
				UnsignedPayload: "p",
				Chain:           "CHAIN_ETHEREUM",
			})
			require.NoError(t, err)
			require.Equal(t, "ipd", result.InputPayloadDigest)
			require.JSONEq(t, bootProof, string(result.RawAttestation))
			require.Empty(t, result.EnclaveApp)
			require.NotContains(t, result.Attestations, BootAttestationKey)
		})
	}
}
