package verify

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	nitroverifier "github.com/anchorageoss/awsnitroverifier"
	"github.com/anchorageoss/visualsign-turnkeyclient/api"
	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
)

// APIClient interface for making API calls
type APIClient interface {
	CreateSignablePayload(ctx context.Context, req *api.CreateSignablePayloadRequest) (*api.SignablePayloadResponse, error)
}

// AttestationVerifier interface for verifying attestations
type AttestationVerifier interface {
	Validate(attestationDocument []byte) (*nitroverifier.ValidationResult, error)
}

// Service handles verification logic
type Service struct {
	apiClient           APIClient
	attestationVerifier AttestationVerifier
}

// NewService creates a new verification service
func NewService(apiClient APIClient, attestationVerifier AttestationVerifier) *Service {
	return &Service{
		apiClient:           apiClient,
		attestationVerifier: attestationVerifier,
	}
}

// Verify performs end-to-end verification of a transaction in an AWS Nitro
// enclave: it calls the configured APIClient to fetch a SignablePayloadResponse
// and then runs the post-fetch verification chain via VerifyResponse.
func (s *Service) Verify(ctx context.Context, req *VerifyRequest) (*VerifyResult, error) {
	if s.apiClient == nil {
		return nil, errors.New("Verify requires an APIClient; use VerifyResponse for pre-fetched responses")
	}
	if req == nil {
		return nil, errors.New("Verify requires a non-nil VerifyRequest")
	}

	chain := req.Chain
	if chain == "" {
		if req.ChainMetadata != nil {
			return nil, fmt.Errorf("chain must be specified when ChainMetadata is set")
		}
		chain = "CHAIN_SOLANA" // default to Solana if not specified
	}
	if req.ChainMetadata != nil && req.ChainMetadata.Ethereum != nil {
		if !strings.HasPrefix(chain, "CHAIN_ETHEREUM") {
			return nil, fmt.Errorf("ChainMetadata.Ethereum requires an Ethereum chain, got %q", chain)
		}
	}
	apiReq := &api.CreateSignablePayloadRequest{
		UnsignedPayload:           req.UnsignedPayload,
		Chain:                     chain,
		ChainMetadata:             req.ChainMetadata,
		IncludeIntermediateOutput: req.IncludeIntermediateOutput,
	}

	response, err := s.apiClient.CreateSignablePayload(ctx, apiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call API: %w", err)
	}

	return s.VerifyResponse(ctx, response, &VerifyResponseRequest{
		UnsignedPayload:    req.UnsignedPayload,
		QosManifestHex:     req.QosManifestHex,
		PivotBinaryHashHex: req.PivotBinaryHashHex,
		SaveManifestPath:   req.SaveManifestPath,
		ChainMetadata:      req.ChainMetadata,
	})
}

// VerifyResponse runs the verification chain on a pre-fetched
// SignablePayloadResponse — used when the response was obtained out-of-band
// (e.g., a backend integration that received the Turnkey response via another
// channel and never makes the API call directly). Equivalent to Steps 2-5 of
// Verify; APIClient is not invoked.
func (s *Service) VerifyResponse(_ context.Context, response *api.SignablePayloadResponse, req *VerifyResponseRequest) (*VerifyResult, error) {
	if response == nil {
		return nil, errors.New("VerifyResponse requires a non-nil SignablePayloadResponse")
	}
	if req == nil {
		return nil, errors.New("VerifyResponse requires a non-nil VerifyResponseRequest")
	}

	result := &VerifyResult{
		PCRs:                    make(map[uint][]byte),
		ManifestReserialization: ManifestSerializationResult{},
	}

	// Save QoS manifest envelope to file if requested
	if req.SaveManifestPath != "" && response.QosManifestEnvelopeB64 != "" {
		envelopeBytes, err := base64.StdEncoding.DecodeString(response.QosManifestEnvelopeB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode manifest envelope: %w", err)
		}
		if err := os.WriteFile(req.SaveManifestPath, envelopeBytes, 0644); err != nil {
			return nil, fmt.Errorf("failed to save manifest envelope: %w", err)
		}
	}

	// Extract attestations from API response
	appAttestation, bootAttestationDoc, err := s.extractAttestations(response)
	if err != nil {
		return nil, err
	}

	// Store attestation data in result
	result.PublicKeyHex = appAttestation.PublicKey
	result.MessageHex = appAttestation.Message
	result.SignatureHex = appAttestation.Signature
	result.SignablePayload = response.SignablePayload
	result.InputPayloadDigest = response.InputPayloadDigest
	result.MetadataDigest = response.MetadataDigest

	// Decode the optional machine-readable intermediate output. Its raw bytes
	// are folded into the signed-message binding below; the decoded struct is
	// surfaced in the result. Presence is driven by the response, not the
	// request flag, so a backend that ignores the flag (e.g. the live API)
	// still verifies. A non-empty-but-undecodable blob is a hard error.
	var intermediateOutputBytes []byte
	if response.IntermediateOutputB64 != "" {
		intermediateOutputBytes, err = base64.StdEncoding.DecodeString(response.IntermediateOutputB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode intermediate output base64: %w", err)
		}
		decoded, err := DecodeSolanaIntermediateOutput(intermediateOutputBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to decode solana intermediate output: %w", err)
		}
		result.IntermediateOutput = decoded
	}

	// Recompute digests locally to confirm the backend-reported values match
	// our inputs. See visualsign-parser's src/parser/app/src/routes/parse.rs:
	//   input_payload_digest = sha256(unsigned_payload_string_bytes)
	//   metadata_digest      = sha256(borsh_encode(chain_metadata))
	// When chain_metadata is nil the expected metadata digest is SHA-256("").
	// When chain_metadata is non-nil the expected digest is SHA-256(Borsh(chain_metadata)),
	// computed locally via RequestChainMetadata.MetadataDigestHex().
	// InputPayloadDigest is best-effort: skipped when the backend omits the
	// field, or when UnsignedPayload is not provided (backend integration path
	// where the original unsigned bytes are not available locally).
	// MetadataDigest is strict when the client sent ChainMetadata — see
	// checkMetadataDigest.
	if response.InputPayloadDigest != "" && req.UnsignedPayload != "" {
		computed := manifest.ComputeHash([]byte(req.UnsignedPayload))
		if computed != response.InputPayloadDigest {
			return nil, fmt.Errorf("inputPayloadDigest mismatch: backend reported %s, computed %s",
				response.InputPayloadDigest, computed)
		}
	}
	if err := checkMetadataDigest(response.MetadataDigest, req.ChainMetadata); err != nil {
		return nil, err
	}

	// Bind appAttestation.Message to (signablePayload, inputPayloadDigest,
	// metadataDigest) by recomputing the Borsh ParsedTransactionPayload hash.
	// Without this, an attacker controlling the transport could substitute
	// signablePayload while keeping a valid signature over an unrelated
	// message hash. Compare as bytes so the binding is insensitive to
	// hex casing and surfaces a clean decode error on malformed input.
	expectedMsg, err := ComputeBorshParsedTransactionPayloadHash(
		response.SignablePayload, response.InputPayloadDigest, response.MetadataDigest,
		intermediateOutputBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("compute borsh parsed transaction payload hash: %w", err)
	}
	actualMsgBytes, err := hex.DecodeString(appAttestation.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to decode message hex: %w", err)
	}
	expectedMsgBytes, _ := hex.DecodeString(expectedMsg) // safe: just produced by hex.EncodeToString
	if !bytes.Equal(expectedMsgBytes, actualMsgBytes) {
		return nil, fmt.Errorf("appAttestation.Message mismatch: enclave reported %s, recomputed %s",
			appAttestation.Message, expectedMsg)
	}

	bootAttestationDocBytes, err := base64.StdEncoding.DecodeString(bootAttestationDoc)
	if err != nil {
		return nil, fmt.Errorf("failed to decode boot attestation document: %w", err)
	}

	// Step 2: Verify attestation document using awsnitroverifier
	validationResult, err := s.attestationVerifier.Validate(bootAttestationDocBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to verify attestation document: %w", err)
	}

	if !validationResult.Valid {
		return nil, fmt.Errorf("attestation document validation failed: %v", validationResult.Errors)
	}

	result.AttestationValid = validationResult.Valid
	result.ModuleID = validationResult.Document.ModuleID
	result.PCRs = validationResult.Document.PCRs
	result.UserData = validationResult.Document.UserData
	result.AttestationDocument = validationResult.Document

	// Bind the public_key embedded in the attestation document to the
	// public key the enclave reports in the app attestation. They must
	// reference the same ephemeral key. Normalise both to the 65-byte
	// SEC1 uncompressed form (0x04 || X || Y) before comparing: the app
	// attestation packs 130 bytes (a prefix concatenated with SEC1), while
	// the Nitro attestation document's public_key field is typically the
	// 65-byte SEC1 key alone. Comparing the raw byte slices would reject
	// legitimate responses whenever those representations differ.
	actualPubKeyBytes, err := hex.DecodeString(appAttestation.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key hex: %w", err)
	}
	appSEC1, err := sec1FromAppPubKey(actualPubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("app attestation public key: %w", err)
	}
	docSEC1, err := sec1FromDocPubKey(validationResult.Document.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("attestation document public key: %w", err)
	}
	if !bytes.Equal(appSEC1, docSEC1) {
		return nil, fmt.Errorf("appAttestation.PublicKey mismatch: attestation document %s, app %s",
			hex.EncodeToString(docSEC1), hex.EncodeToString(appSEC1))
	}

	// Capture PCR validation results if any PCR rules were provided
	if len(validationResult.PCRResults) > 0 {
		result.PCRValidationResults = make([]PCRValidationResult, len(validationResult.PCRResults))
		for i, pcrResult := range validationResult.PCRResults {
			result.PCRValidationResults[i] = PCRValidationResult{
				Index:    pcrResult.Index,
				Expected: hex.EncodeToString(pcrResult.Expected),
				Actual:   hex.EncodeToString(pcrResult.Actual),
				Valid:    pcrResult.Valid,
			}
		}
	}

	// Extract and set QoS manifest hash from UserData early, so it's available
	// even if manifest processing fails later
	if len(result.UserData) > 0 {
		result.QosManifestHash = hex.EncodeToString(result.UserData)
		result.PivotBinaryHash = hex.EncodeToString(result.UserData)
	}

	// Verify UserData against provided QoS manifest if given
	if req.QosManifestHex != "" {
		if err := s.verifyUserData(validationResult.Document.UserData, req.QosManifestHex); err != nil {
			return nil, fmt.Errorf("QoS manifest verification failed: %w", err)
		}
	}

	// Also check against pivot binary hash if provided
	if req.PivotBinaryHashHex != "" && req.QosManifestHex == "" {
		if err := s.verifyUserData(validationResult.Document.UserData, req.PivotBinaryHashHex); err != nil {
			return nil, fmt.Errorf("pivot binary hash verification failed: %w", err)
		}
	}

	// Step 3: Extract and verify public key
	publicKeyForVerification, err := s.extractPublicKey(appAttestation.PublicKey)
	if err != nil {
		return nil, err
	}
	result.PublicKey = publicKeyForVerification

	// Step 4: Verify signature
	messageBytes, err := hex.DecodeString(appAttestation.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to decode message hex: %w", err)
	}

	signatureBytes, err := hex.DecodeString(appAttestation.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature hex: %w", err)
	}

	// The signature is over the SHA256 hash of the message hash
	sha256Hash := sha256.Sum256(messageBytes)
	signatureValid := ecdsa.Verify(publicKeyForVerification, sha256Hash[:],
		new(big.Int).SetBytes(signatureBytes[:32]),
		new(big.Int).SetBytes(signatureBytes[32:]))

	if !signatureValid {
		return nil, errors.New("signature verification failed")
	}

	result.SignatureValid = true
	result.Valid = true

	// Step 5: Decode QoS Manifest if available
	if response.QosManifestB64 != "" || response.QosManifestEnvelopeB64 != "" {
		if err := s.processManifest(response, validationResult.Document.UserData, result); err != nil {
			return nil, err
		}
	}

	// Add PCR[4] if present
	if pcr4, exists := result.PCRs[4]; exists && len(pcr4) > 0 {
		result.PCR4 = hex.EncodeToString(pcr4)
	}

	return result, nil
}

// extractAttestations extracts and parses attestations from API response
func (s *Service) extractAttestations(response *api.SignablePayloadResponse) (*AppAttestation, string, error) {
	attestationJSON, ok := response.Attestations[api.AppAttestationKey]
	if !ok {
		return nil, "", errors.New("no app attestation found in response")
	}

	var appAttestation AppAttestation
	if err := json.Unmarshal([]byte(attestationJSON), &appAttestation); err != nil {
		return nil, "", fmt.Errorf("failed to parse app attestation: %w", err)
	}

	bootAttestationDoc, ok := response.Attestations[api.BootAttestationKey]
	if !ok {
		return nil, "", errors.New("no boot attestation found in response")
	}

	return &appAttestation, bootAttestationDoc, nil
}

// sec1FromAppPubKey normalises the public_key field reported by the enclave
// in its app attestation (130 bytes: prefix || SEC1) down to the 65-byte
// SEC1 uncompressed form.
func sec1FromAppPubKey(b []byte) ([]byte, error) {
	if len(b) != 130 {
		return nil, fmt.Errorf("expected 130-byte app public key, got %d bytes", len(b))
	}
	sec1 := b[65:]
	if sec1[0] != 0x04 {
		return nil, fmt.Errorf("expected uncompressed SEC1 prefix (0x04), got 0x%02x", sec1[0])
	}
	return sec1, nil
}

// sec1FromDocPubKey normalises the public_key field of the Nitro attestation
// document. The enclave may store the 65-byte SEC1 key directly, or the same
// 130-byte form used by the app attestation; accept either and return SEC1.
func sec1FromDocPubKey(b []byte) ([]byte, error) {
	switch len(b) {
	case 65:
		if b[0] != 0x04 {
			return nil, fmt.Errorf("expected uncompressed SEC1 prefix (0x04), got 0x%02x", b[0])
		}
		return b, nil
	case 130:
		return sec1FromAppPubKey(b)
	default:
		return nil, fmt.Errorf("expected 65- or 130-byte public key, got %d bytes", len(b))
	}
}

// extractPublicKey extracts the 65-byte public key from the 130-byte hex string
func (s *Service) extractPublicKey(publicKeyHex string) (*ecdsa.PublicKey, error) {
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key hex: %w", err)
	}

	if len(publicKeyBytes) != 130 {
		return nil, fmt.Errorf("expected 130-byte public key, got %d bytes", len(publicKeyBytes))
	}

	// Extract the latter 65 bytes (uncompressed public key format: 0x04 || X || Y)
	publicKeyForVerification := publicKeyBytes[65:]

	if publicKeyForVerification[0] != 0x04 {
		return nil, fmt.Errorf("expected uncompressed public key format (0x04 prefix), got 0x%02x", publicKeyForVerification[0])
	}

	// P-256 curve
	curve := elliptic.P256()
	keyLen := 32
	x := new(big.Int).SetBytes(publicKeyForVerification[1 : 1+keyLen])
	y := new(big.Int).SetBytes(publicKeyForVerification[1+keyLen:])

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Verify the public key is on the curve using crypto/ecdh (non-deprecated API)
	if _, err := ecdh.P256().NewPublicKey(publicKeyForVerification); err != nil {
		return nil, fmt.Errorf("public key is not on the P256 curve: %w", err)
	}

	return pubKey, nil
}

// verifyUserData verifies that UserData matches the provided hash
func (s *Service) verifyUserData(userData []byte, expectedHashHex string) error {
	expectedHashBytes, err := hex.DecodeString(expectedHashHex)
	if err != nil {
		return fmt.Errorf("invalid hash hex provided: %w", err)
	}

	if hex.EncodeToString(expectedHashBytes) != hex.EncodeToString(userData) {
		return fmt.Errorf("hash mismatch: expected %s, got %s",
			expectedHashHex, hex.EncodeToString(userData))
	}

	return nil
}

// processManifest decodes and processes the QoS manifest
func (s *Service) processManifest(response *api.SignablePayloadResponse, userData []byte,
	result *VerifyResult) error {

	// Skip if no manifest provided
	if response.QosManifestB64 == "" && response.QosManifestEnvelopeB64 == "" {
		return nil
	}

	// Compute raw manifest hash only when raw manifest data is present
	var rawManifestHash string
	if response.QosManifestB64 != "" {
		rawManifestBytes, err := base64.StdEncoding.DecodeString(response.QosManifestB64)
		if err == nil {
			rawManifestHash = manifest.ComputeHash(rawManifestBytes)
		}
	}

	var envelopeBytes []byte
	var envelopeBase64Err error
	isJSONEnvelope := false
	if response.QosManifestEnvelopeB64 != "" {
		envelopeBytes, envelopeBase64Err = base64.StdEncoding.DecodeString(response.QosManifestEnvelopeB64)
		if envelopeBase64Err == nil {
			isJSONEnvelope = manifest.DetectEnvelopeFormat(envelopeBytes) == manifest.EnvelopeFormatJSON
		}
	}

	mv := response.ManifestVersion
	// Only fast-fail on a missing manifest version when we've confirmed the
	// envelope isn't JSON (or there's no envelope at all): a Borsh-shaped
	// (or absent) envelope genuinely can't be decoded without knowing V1 vs
	// V2. When the envelope's base64 itself failed to decode, fall through
	// instead, so the real base64 error (and the raw-manifest fallback
	// below) aren't masked by this generic message.
	if !isJSONEnvelope && envelopeBase64Err == nil && mv == manifest.ManifestVersionUnknown {
		return fmt.Errorf("manifest version not set on API response (must be V1 or V2)")
	}

	// Try to decode the manifest envelope if available, otherwise use raw manifest
	var decodedManifest *manifest.Manifest
	var manifestBytes []byte
	var err error
	var envelopeErr error
	if response.QosManifestEnvelopeB64 != "" {
		if envelopeBase64Err != nil {
			envelopeErr = fmt.Errorf("failed to decode base64: %w", envelopeBase64Err)
		} else {
			_, decodedManifest, manifestBytes, _, envelopeErr = manifest.DecodeManifestEnvelopeFromBytes(envelopeBytes, mv)
		}
		err = envelopeErr
	}
	// Only fall back to the raw-manifest path when the envelope itself was
	// not JSON-shaped (or absent): a JSON envelope that fails strict
	// decoding must fail with that decode error, never be silently retried
	// against a Borsh-decoded raw manifest, which would apply the
	// JSON-only canonical-hash match rule below to bytes that were never
	// actually JSON.
	if !isJSONEnvelope && (err != nil || decodedManifest == nil) && response.QosManifestB64 != "" {
		decodedManifest, manifestBytes, err = manifest.DecodeRawManifestFromBase64(response.QosManifestB64, mv)
		if err != nil && envelopeErr != nil {
			err = fmt.Errorf("envelope decode failed: %v; raw manifest decode failed: %w", envelopeErr, err)
		}
	}
	if err != nil {
		// Store what we know for debugging, even if parsing failed
		result.ManifestReserialization.RawManifestHash = rawManifestHash
		result.ManifestReserialization.RawManifestB64 = response.QosManifestB64
		result.ManifestReserialization.EnvelopeB64 = response.QosManifestEnvelopeB64
		if len(userData) > 0 {
			result.ManifestReserialization.UserDataHash = hex.EncodeToString(userData)
		}
		return fmt.Errorf("failed to decode QoS manifest: %w", err)
	}

	result.Manifest = decodedManifest

	// Compute reserialized hash
	reserializedManifestHash := manifest.ComputeHash(manifestBytes)

	serializationResult := ManifestSerializationResult{
		RawManifestHash:          rawManifestHash,
		ReserializedManifestHash: reserializedManifestHash,
	}

	// Compute the envelope hash whenever the envelope base64 decoded, even if
	// it then failed to deserialize as a manifest envelope: this hash is
	// surfaced for debugging (cmd/verify.go prints it regardless of match
	// outcome). base64.StdEncoding.DecodeString returns a non-nil partial
	// slice even on error, so guard on the decode error, not on slice
	// nilness, or a decode failure would leak a hash of garbage bytes here.
	// The security-relevant "matches" check below additionally requires
	// envelopeErr == nil, so this hash alone can never satisfy the binding
	// unless the envelope actually decoded.
	if response.QosManifestEnvelopeB64 != "" && envelopeBase64Err == nil {
		serializationResult.EnvelopeHash = manifest.ComputeHash(envelopeBytes)
	}

	// Compare against UserData
	if len(userData) > 0 {
		userDataHex := hex.EncodeToString(userData)
		serializationResult.UserDataHash = userDataHex

		// A JSON manifest binds exclusively to its QOS canonical JSON
		// (reserialized) hash: accepting a raw or envelope hash match here
		// would let a non-canonical encoding of the same manifest satisfy the
		// binding, defeating the point of canonicalizing before hashing.
		reserializedMatches := reserializedManifestHash == userDataHex
		var matches bool
		var matchedVia string
		if isJSONEnvelope {
			matches = reserializedMatches
			if matches {
				matchedVia = "canonical"
			}
		} else {
			rawManifestMatches := rawManifestHash != "" && rawManifestHash == userDataHex
			// envelopeErr == nil is required here (not just a hash match):
			// otherwise a decode failure that still fell back to the
			// raw-manifest path (decodedManifest/manifestBytes above) could
			// have its binding satisfied by the hash of envelope bytes that
			// were never verified to encode anything, even though the
			// manifest actually processed and displayed came from the
			// raw-manifest field instead.
			envelopeMatches := envelopeErr == nil && serializationResult.EnvelopeHash != "" && serializationResult.EnvelopeHash == userDataHex
			matches = rawManifestMatches || reserializedMatches || envelopeMatches
			switch {
			case rawManifestMatches:
				matchedVia = "raw"
			case reserializedMatches:
				matchedVia = "reserialized"
			case envelopeMatches:
				matchedVia = "envelope"
			}
		}

		if matches {
			serializationResult.Matches = true
			serializationResult.MatchedVia = matchedVia
		} else {
			serializationResult.ReserializationNeeded = true
			mismatchMsg := fmt.Sprintf(
				"manifest hash mismatch: boot-time %s", userDataHex)
			if rawManifestHash != "" {
				mismatchMsg += fmt.Sprintf(" != raw-manifest %s", rawManifestHash)
			}
			mismatchMsg += fmt.Sprintf(" != reserialized %s", reserializedManifestHash)
			if serializationResult.EnvelopeHash != "" {
				mismatchMsg += fmt.Sprintf(" != envelope %s", serializationResult.EnvelopeHash)
			}
			serializationResult.Error = mismatchMsg
			return errors.New(serializationResult.Error)
		}

		// Store result hashes for output
		result.QosManifestHash = userDataHex
		result.PivotBinaryHash = userDataHex
	}

	result.ManifestReserialization = serializationResult
	return nil
}

// AppAttestation represents the parsed app attestation structure
type AppAttestation struct {
	Message   string `json:"message"`
	PublicKey string `json:"publicKey"`
	Scheme    string `json:"scheme"`
	Signature string `json:"signature"`
}

// emptyMetadataDigestHex is SHA-256 of an empty byte slice. The visualsign
// parser produces this digest when no chain_metadata is supplied.
var emptyMetadataDigestHex = manifest.ComputeHash([]byte{})

// checkMetadataDigest validates the metadataDigest from the backend.
//
// When the client sends ChainMetadata, the backend MUST return a non-empty
// metadataDigest so the recompute-and-compare check can run; an empty digest
// here would silently skip verification of exactly the field the caller asked
// us to verify.
//
// When the client sends no ChainMetadata, an empty digest is treated as the
// backend omitting an optional field (older versions) and the check is skipped.
func checkMetadataDigest(digest string, chainMetadata *api.RequestChainMetadata) error {
	if chainMetadata == nil {
		if digest == "" {
			return nil
		}
		if digest != emptyMetadataDigestHex {
			return fmt.Errorf("metadataDigest mismatch: backend reported %s, expected %s (client sent no chain_metadata)",
				digest, emptyMetadataDigestHex)
		}
		return nil
	}
	if digest == "" {
		return fmt.Errorf("backend did not return metadataDigest but client sent chain_metadata; cannot verify ABI round-trip")
	}
	expected, err := chainMetadata.MetadataDigestHex()
	if err != nil {
		return fmt.Errorf("failed to compute expected metadataDigest: %w", err)
	}
	if digest != expected {
		return fmt.Errorf("metadataDigest mismatch: backend reported %s, computed %s",
			digest, expected)
	}
	return nil
}
