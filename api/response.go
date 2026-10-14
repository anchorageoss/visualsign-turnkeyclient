package api

import (
	"encoding/json"
	"fmt"
)

// ParseSignablePayloadResponse converts the raw JSON body of a Turnkey
// VisualSign parse response into a SignablePayloadResponse, ready for
// verify.Service.VerifyResponse.
//
// It is what Client.CreateSignablePayload applies to the HTTP body, exported so
// a response obtained any other way (a saved capture, a backend that received
// the response out-of-band, a test fixture) can be verified without making an
// API call. It performs no verification itself. A response whose top-level
// "error" field is set is returned as an error.
func ParseSignablePayloadResponse(bodyBytes []byte) (*SignablePayloadResponse, error) {
	var turnkeyResp TurnkeyVisualSignResponse

	if err := json.Unmarshal(bodyBytes, &turnkeyResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
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

	return &SignablePayloadResponse{
		SignablePayload:                  signablePayloadString,
		ParsedPayload:                    turnkeyResp.Response.ParsedTransaction.Payload.ParsedPayload,
		InputPayloadDigest:               turnkeyResp.Response.ParsedTransaction.Payload.InputPayloadDigest,
		MetadataDigest:                   turnkeyResp.Response.ParsedTransaction.Payload.MetadataDigest,
		IntermediateOutputB64:            turnkeyResp.Response.ParsedTransaction.Payload.IntermediateOutput,
		TurnkeySerializedSignablePayload: signablePayloadString,
		Attestations:                     attestations,
		QosManifestB64:                   qosManifestB64,
		QosManifestEnvelopeB64:           qosManifestEnvelopeB64,
		EphemeralPublicKeyHex:            ephemeralPublicKeyHex,
		EnclaveApp:                       enclaveApp,
		DeploymentLabel:                  deploymentLabel,
	}, nil
}
