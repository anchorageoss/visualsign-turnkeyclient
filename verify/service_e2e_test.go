package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	nitroverifier "github.com/anchorageoss/awsnitroverifier"
	"github.com/anchorageoss/visualsign-turnkeyclient/api"
	"github.com/anchorageoss/visualsign-turnkeyclient/testdata"
	"github.com/stretchr/testify/require"
)

// TestVerifyEndToEnd_IntermediateOutputAgainstGatewayResponse drives the whole
// verify pipeline against a real response captured from the local parser
// gateway (with include_intermediate_output=true): the real api.Client maps the
// wire response, and VerifyResponse runs the Borsh message binding (including
// the appended intermediate output), the ECDSA signature check against the
// enclave's real ephemeral key, the public-key binding, and the intermediate
// Borsh decode.
//
// Only the attestation verifier is mocked. That is unavoidable and correct: the
// gateway emits a KNOWN mock boot proof ("TURNKEY_GATEWAY_MOCK_BOOT_PROOF") for
// non-TEE local dev, which real Nitro attestation legitimately rejects. We
// stand in a verifier that reports Valid and echoes the enclave's public key so
// the binding check is still exercised. The mock QoS-manifest sentinels in the
// boot proof are likewise not real manifests, so manifest processing is skipped
// by clearing those fields — everything else is real parser output.
func TestVerifyEndToEnd_IntermediateOutputAgainstGatewayResponse(t *testing.T) {
	// Replay the captured gateway response over HTTP so the real api.Client
	// performs the wire→struct mapping, including the new intermediateOutput.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/visualsign/api/v2/parse", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(testdata.SolanaIntermediateGatewayResponseJSON)
	}))
	defer server.Close()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	client := &api.Client{
		HostURI:              server.URL,
		HTTPClient:           &http.Client{},
		APIKey:               &api.TurnkeyAPIKey{PublicKey: "test", PrivateKey: privKey, OrganizationID: "test-org"},
		VisualSignAPIVersion: "v2",
	}

	unsignedPayload := strings.TrimSpace(string(testdata.SolanaIntermediateUnsignedPayload))
	resp, err := client.CreateSignablePayload(context.Background(), &api.CreateSignablePayloadRequest{
		UnsignedPayload:           unsignedPayload,
		Chain:                     "CHAIN_SOLANA",
		IncludeIntermediateOutput: true,
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.IntermediateOutputB64, "gateway response must carry base64 intermediate output")

	// The mock boot proof's QoS-manifest fields are sentinels, not real
	// manifests; clear them so verification isn't gated on decoding them.
	resp.QosManifestB64 = ""
	resp.QosManifestEnvelopeB64 = ""

	// Build a verifier that echoes the enclave's real public key (65-byte SEC1),
	// so the public-key binding is genuinely checked.
	mockVerifier := &mockAttestationVerifier{
		result: &nitroverifier.ValidationResult{
			Valid: true,
			Document: &nitroverifier.AttestationDocument{
				ModuleID:  "mock-local-gateway",
				PCRs:      map[uint][]byte{},
				UserData:  []byte{},
				PublicKey: appAttestationSEC1(t, resp),
			},
		},
	}

	service := NewService(client, mockVerifier)
	result, err := service.VerifyResponse(context.Background(), resp, &VerifyResponseRequest{
		UnsignedPayload: unsignedPayload,
		Chain:           "CHAIN_SOLANA",
	})
	require.NoError(t, err)
	require.True(t, result.Valid)
	require.True(t, result.SignatureValid)
	require.True(t, result.AttestationValid)

	// The intermediate output decoded end-to-end.
	require.NotNil(t, result.IntermediateOutput)
	require.Equal(t, uint16(4), result.IntermediateOutput.SchemaVersion)
	require.Nil(t, result.IntermediateOutput.NativeInstructionDecoder, "schema_version 4 carries no native_instruction_decoder")
	require.Len(t, result.IntermediateOutput.Transfers, 1)
	require.Equal(t, "1000000000", result.IntermediateOutput.Transfers[0].Amount)
}

// TestVerifyEndToEnd_RealV5Captures runs each real schema_version 5 response
// captured from parser PR #575 through the same pipeline as
// TestVerifyEndToEnd_IntermediateOutputAgainstGatewayResponse: api.Client wire
// mapping, VerifyResponse with Chain CHAIN_SOLANA, the inputPayloadDigest
// check, the signed-message binding over the appended intermediate output,
// the ECDSA signature and public-key binding, and the schema_version 5 decode.
// Only the attestation verifier is mocked, for the reasons given there.
func TestVerifyEndToEnd_RealV5Captures(t *testing.T) {
	for _, c := range loadSolanaV5Captures(t) {
		t.Run(c.Name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/visualsign/api/v2/parse", r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(c.GatewayResponse)
			}))
			defer server.Close()

			privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			client := &api.Client{
				HostURI:              server.URL,
				HTTPClient:           &http.Client{},
				APIKey:               &api.TurnkeyAPIKey{PublicKey: "test", PrivateKey: privKey, OrganizationID: "test-org"},
				VisualSignAPIVersion: "v2",
			}

			resp, err := client.CreateSignablePayload(context.Background(), &api.CreateSignablePayloadRequest{
				UnsignedPayload:           c.UnsignedPayload,
				Chain:                     "CHAIN_SOLANA",
				IncludeIntermediateOutput: true,
			})
			require.NoError(t, err)
			require.NotEmpty(t, resp.IntermediateOutputB64)
			resp.QosManifestB64 = ""
			resp.QosManifestEnvelopeB64 = ""

			mockVerifier := &mockAttestationVerifier{
				result: &nitroverifier.ValidationResult{
					Valid: true,
					Document: &nitroverifier.AttestationDocument{
						ModuleID:  "mock-local-gateway",
						PCRs:      map[uint][]byte{},
						UserData:  []byte{},
						PublicKey: appAttestationSEC1(t, resp),
					},
				},
			}

			service := NewService(client, mockVerifier)
			result, err := service.VerifyResponse(context.Background(), resp, &VerifyResponseRequest{
				UnsignedPayload: c.UnsignedPayload,
				Chain:           "CHAIN_SOLANA",
			})
			require.NoError(t, err)
			require.True(t, result.Valid)
			require.True(t, result.SignatureValid)
			require.True(t, result.AttestationValid)

			require.NotNil(t, result.IntermediateOutput)
			require.Equal(t, uint16(5), result.IntermediateOutput.SchemaVersion)
			require.NotNil(t, result.IntermediateOutput.NativeInstructionDecoder)
			require.Equal(t, SolanaNativeInstructionDecoderJSONParsed, *result.IntermediateOutput.NativeInstructionDecoder)
			require.NotEmpty(t, result.IntermediateOutput.Instructions)

			// Rewriting the output as schema_version 4 (version changed,
			// decoder byte dropped) still decodes, but must break the message
			// binding: the version and the decoder byte are signed.
			v5raw, err := base64.StdEncoding.DecodeString(resp.IntermediateOutputB64)
			require.NoError(t, err)
			tampered := append([]byte{4, 0}, v5raw[3:]...)
			resp.IntermediateOutputB64 = base64.StdEncoding.EncodeToString(tampered)
			_, err = service.VerifyResponse(context.Background(), resp, &VerifyResponseRequest{
				UnsignedPayload: c.UnsignedPayload,
				Chain:           "CHAIN_SOLANA",
			})
			require.ErrorContains(t, err, "appAttestation.Message mismatch")
		})
	}
}

// appAttestationSEC1 extracts the 65-byte SEC1 public key from the app
// attestation the enclave reported (130 bytes: prefix || SEC1).
func appAttestationSEC1(t *testing.T, resp *api.SignablePayloadResponse) []byte {
	t.Helper()
	var app struct {
		PublicKey string `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal([]byte(resp.Attestations[api.AppAttestationKey]), &app))
	raw, err := hex.DecodeString(app.PublicKey)
	require.NoError(t, err)
	require.Len(t, raw, 130)
	return raw[65:]
}
