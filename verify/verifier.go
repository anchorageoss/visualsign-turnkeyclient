package verify

import (
	"context"
	"fmt"

	"github.com/anchorageoss/visualsign-turnkeyclient/api"
)

// Verifier verifies a parsed payload response produced by the parse client.
// Implementations read whatever attestation/signature the deployment attaches
// to the SignablePayloadResponse (e.g. an AWS Nitro attestation document, or a
// custom sibling attestation object exposed via RawAttestation).
type Verifier interface {
	Verify(ctx context.Context, resp *api.SignablePayloadResponse) (*VerifierResult, error)
}

// VerifierResult is the outcome of a Verifier.Verify call.
type VerifierResult struct {
	// OK is true when the verifier accepted the response.
	OK bool `json:"ok"`
	// Detail is a human-readable summary of the verification outcome.
	Detail string `json:"detail,omitempty"`
	// Signed optionally carries verifier-recovered signed data (e.g. digests
	// bound into an attestation), for downstream inspection.
	Signed map[string]string `json:"signed,omitempty"`
}

// RunVerify builds the request, calls the parse client to obtain a parsed
// SignablePayloadResponse, and hands that response to v for verification. It
// returns both the parsed response and the verifier's result.
//
// On a client error the verifier is not invoked and (nil, nil, err) is
// returned. A verifier that returns an error likewise surfaces as
// (resp, nil, err). A successful verification returns (resp, result, nil).
func RunVerify(ctx context.Context, c *api.Client, req *api.CreateSignablePayloadRequest, v Verifier) (*api.SignablePayloadResponse, *VerifierResult, error) {
	if c == nil {
		return nil, nil, fmt.Errorf("RunVerify requires a non-nil api.Client")
	}
	if req == nil {
		return nil, nil, fmt.Errorf("RunVerify requires a non-nil request")
	}
	if v == nil {
		return nil, nil, fmt.Errorf("RunVerify requires a non-nil Verifier")
	}

	resp, err := c.CreateSignablePayload(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse payload: %w", err)
	}

	result, err := v.Verify(ctx, resp)
	if err != nil {
		return resp, nil, fmt.Errorf("verifier failed: %w", err)
	}

	return resp, result, nil
}
