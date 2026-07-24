package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	nitroverifier "github.com/anchorageoss/awsnitroverifier"
	"github.com/anchorageoss/visualsign-turnkeyclient/api"
	"github.com/stretchr/testify/require"
)

// TestServiceVerifierImplementsVerifier confirms the legacy Nitro flow is
// exposed through the generic Verifier interface via the ServiceVerifier
// adapter.
func TestServiceVerifierImplementsVerifier(t *testing.T) {
	var _ Verifier = (*ServiceVerifier)(nil)
}

// TestServiceVerifier_SignatureFailure exercises ServiceVerifier.Verify (the
// Verifier interface method) over a pre-fetched response and asserts it
// surfaces the legacy signature-verification failure as an error.
func TestServiceVerifier_SignatureFailure(t *testing.T) {
	pubKeyBytes, _ := create130BytePublicKey(t)
	validKey260 := hex.EncodeToString(pubKeyBytes)
	messageHex := expectedMessageHex(t, "test-payload", "", "")
	signatureHex := strings.Repeat("ab", 64)
	appAttJSON := fmt.Sprintf(`{"message":"%s","publicKey":"%s","signature":"%s"}`, messageHex, validKey260, signatureHex)
	bootAttB64 := base64.StdEncoding.EncodeToString([]byte("boot-doc"))

	response := &api.SignablePayloadResponse{
		SignablePayload: "test-payload",
		Attestations: map[api.AttestationType]string{
			api.AppAttestationKey:  appAttJSON,
			api.BootAttestationKey: bootAttB64,
		},
	}

	attVerifier := &mockAttestationVerifier{
		result: &nitroverifier.ValidationResult{
			Valid:    true,
			Document: &nitroverifier.AttestationDocument{PublicKey: pubKeyBytes},
		},
	}
	svc := NewService(nil, attVerifier)
	v := NewServiceVerifier(svc, &VerifyResponseRequest{UnsignedPayload: "unsigned-payload"})

	result, err := v.Verify(context.Background(), response)
	require.Error(t, err) // bogus signature fails
	require.Nil(t, result)
	require.Contains(t, err.Error(), "signature verification failed")
}

// sha256Sum returns the SHA-256 digest of b.
func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// TestServiceVerifier_Success verifies that when the full Nitro chain passes,
// ServiceVerifier.Verify (Verifier interface) returns OK=true with the signed
// digests recovered from the response.
func TestServiceVerifier_Success(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pub := privKey.PublicKey
	x := pub.X.Bytes()
	y := pub.Y.Bytes()
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(x):], x)
	copy(yPadded[32-len(y):], y)
	pubKeyBytes := make([]byte, 130)
	pubKeyBytes[0] = 0x04
	copy(pubKeyBytes[1:33], xPadded)
	copy(pubKeyBytes[33:65], yPadded)
	pubKeyBytes[65] = 0x04
	copy(pubKeyBytes[66:98], xPadded)
	copy(pubKeyBytes[98:130], yPadded)
	validKey260 := hex.EncodeToString(pubKeyBytes)

	inputDigest := hex.EncodeToString(sha256Sum([]byte("test-payload")))
	metadataDigest := emptyMetadataDigestHex // SHA-256("") for nil chain metadata
	messageHex := expectedMessageHex(t, "test-payload", inputDigest, metadataDigest)
	msgBytes, err := hex.DecodeString(messageHex)
	require.NoError(t, err)
	sha := sha256.Sum256(msgBytes)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, sha[:])
	require.NoError(t, err)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)
	signatureHex := hex.EncodeToString(append(rPadded, sPadded...))

	appAttJSON := fmt.Sprintf(`{"message":"%s","publicKey":"%s","signature":"%s"}`, messageHex, validKey260, signatureHex)
	bootAttB64 := base64.StdEncoding.EncodeToString([]byte("boot-doc"))

	response := &api.SignablePayloadResponse{
		SignablePayload:    "test-payload",
		InputPayloadDigest: inputDigest,
		MetadataDigest:     metadataDigest,
		Attestations: map[api.AttestationType]string{
			api.AppAttestationKey:  appAttJSON,
			api.BootAttestationKey: bootAttB64,
		},
	}

	attVerifier := &mockAttestationVerifier{
		result: &nitroverifier.ValidationResult{
			Valid:    true,
			Document: &nitroverifier.AttestationDocument{PublicKey: pubKeyBytes},
		},
	}
	svc := NewService(nil, attVerifier)
	v := NewServiceVerifier(svc, &VerifyResponseRequest{UnsignedPayload: "test-payload"})

	result, err := v.Verify(context.Background(), response)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.OK)
	require.NotEmpty(t, result.Detail)
	// Signed carries the response digests so downstream consumers can inspect
	// what the verifier bound against.
	require.Equal(t, inputDigest, result.Signed["inputPayloadDigest"])
	require.Equal(t, metadataDigest, result.Signed["metadataDigest"])
}
