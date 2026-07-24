package verify

import (
	"context"
	"fmt"

	"github.com/anchorageoss/visualsign-turnkeyclient/api"
)

// ServiceVerifier adapts the existing Nitro verification flow (Service) to the
// generic Verifier interface. It runs VerifyResponse over a pre-fetched
// SignablePayloadResponse using the request fields supplied at construction.
// This keeps the legacy Turnkey/Nitro path unchanged while letting it run
// through the generic RunVerify orchestration.
type ServiceVerifier struct {
	service *Service
	req     *VerifyResponseRequest
}

// NewServiceVerifier wraps a Service so it satisfies the Verifier interface.
// req carries the UnsignedPayload/ChainMetadata/etc. that VerifyResponse needs
// in addition to the SignablePayloadResponse handed to Verify.
func NewServiceVerifier(service *Service, req *VerifyResponseRequest) *ServiceVerifier {
	if req == nil {
		req = &VerifyResponseRequest{}
	}
	return &ServiceVerifier{service: service, req: req}
}

// Verify implements Verifier by delegating to Service.VerifyResponse. On a
// successful legacy verification it returns a VerifierResult with OK=true and
// the response digests surfaced in Signed. On failure it returns the error and
// a nil result, mirroring the legacy behavior.
func (s *ServiceVerifier) Verify(ctx context.Context, resp *api.SignablePayloadResponse) (*VerifierResult, error) {
	if s == nil || s.service == nil {
		return nil, fmt.Errorf("ServiceVerifier.Verify: nil service")
	}
	if resp == nil {
		return nil, fmt.Errorf("ServiceVerifier.Verify: nil response")
	}
	legacy, err := s.service.VerifyResponse(ctx, resp, s.req)
	if err != nil {
		return nil, err
	}
	return &VerifierResult{
		OK:     legacy.Valid,
		Detail: fmt.Sprintf("attestationValid=%v signatureValid=%v", legacy.AttestationValid, legacy.SignatureValid),
		Signed: map[string]string{
			"inputPayloadDigest": legacy.InputPayloadDigest,
			"metadataDigest":     legacy.MetadataDigest,
		},
	}, nil
}
