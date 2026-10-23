package api

import (
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/testdata"
	"github.com/stretchr/testify/require"
)

func TestParseSignablePayloadResponse(t *testing.T) {
	resp, err := ParseSignablePayloadResponse(testdata.TVCResponseNSMJSON)
	require.NoError(t, err)

	require.NotEmpty(t, resp.SignablePayload)
	require.Equal(t, resp.SignablePayload, resp.TurnkeySerializedSignablePayload)
	require.Equal(t, "464f989a0fbe612459941ce280e37e880b773dd7a31967b95e10dfb5ec97cf15", resp.InputPayloadDigest)
	require.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", resp.MetadataDigest)
	require.Equal(t, "visualsign-parser", resp.EnclaveApp)
	require.NotEmpty(t, resp.QosManifestB64)
	require.NotEmpty(t, resp.QosManifestEnvelopeB64)
	require.NotEmpty(t, resp.EphemeralPublicKeyHex)
	require.NotEmpty(t, resp.Attestations[BootAttestationKey])
	require.Contains(t, resp.Attestations[AppAttestationKey], `"signature"`)
}

func TestParseSignablePayloadResponseWithoutBootProof(t *testing.T) {
	body := `{"response":{"parsedTransaction":{"payload":{"signablePayload":"{}"}}}}`
	resp, err := ParseSignablePayloadResponse([]byte(body))
	require.NoError(t, err)
	require.Equal(t, "{}", resp.SignablePayload)
	require.Empty(t, resp.Attestations)
	require.Empty(t, resp.QosManifestB64)
}

func TestParseSignablePayloadResponseErrors(t *testing.T) {
	_, err := ParseSignablePayloadResponse([]byte(`{"error":"payment required"}`))
	require.ErrorContains(t, err, "turnkey API returned error: payment required")

	_, err = ParseSignablePayloadResponse([]byte(`not json`))
	require.ErrorContains(t, err, "failed to decode response")
}
