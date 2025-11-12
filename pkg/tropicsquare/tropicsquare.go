// Package tropicsquare provides integration with Tropic Square TROPIC01 secure element
// for hardware-accelerated cryptographic verification.
//
// This package is currently a skeleton waiting for the libtropic SDK to be published.
// Once the SDK is available, the CGo bindings in libtropic_cgo.go will be implemented.
package tropicsquare

import (
	"crypto/sha256"
	"fmt"
)

// MinimalVerifier uses Tropic Square hardware for signature verification
type MinimalVerifier struct {
	device *Device
}

// NewMinimalVerifier creates a new minimal verifier using Tropic Square hardware
func NewMinimalVerifier() (*MinimalVerifier, error) {
	device, err := NewDevice()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Tropic Square device: %w", err)
	}

	return &MinimalVerifier{
		device: device,
	}, nil
}

// VerifyAttestation verifies pre-processed attestation data using libtropic
//
// This expects data that has been extracted from a full AWS Nitro attestation
// document by a server. The server should:
//  1. Parse the CBOR attestation document
//  2. Validate the certificate chain
//  3. Extract the signing public key, message, and signature
//  4. Send only these components for verification
//
// Parameters:
//   - publicKey: 65-byte uncompressed P-256 public key (0x04 || X || Y)
//   - message: The message that was signed
//   - signature: 64-byte signature (r || s, each 32 bytes)
//
// Returns nil if verification succeeds, error otherwise.
//
// Note: libtropic expects 64-byte public keys (X || Y without 0x04 prefix),
// so we strip the prefix if present.
func (v *MinimalVerifier) VerifyAttestation(
	publicKey []byte,
	message []byte,
	signature []byte,
) error {
	// Validate inputs
	if len(publicKey) != 65 && len(publicKey) != 64 {
		return fmt.Errorf("invalid public key length: expected 65 or 64 bytes, got %d", len(publicKey))
	}

	// Strip 0x04 prefix if present (libtropic expects 64-byte keys)
	pubkeyForVerification := publicKey
	if len(publicKey) == 65 {
		if publicKey[0] != 0x04 {
			return fmt.Errorf("invalid public key format: expected uncompressed format (0x04 prefix)")
		}
		pubkeyForVerification = publicKey[1:] // Strip prefix
	}

	if len(signature) != 64 {
		return fmt.Errorf("invalid signature length: expected 64 bytes, got %d", len(signature))
	}

	// Hash the message with SHA256
	// The signature is over the hash, not the raw message
	hash := sha256.Sum256(message)

	// Use libtropic ECDSA verification (software, host-side)
	valid, err := v.device.VerifyECDSA_P256(pubkeyForVerification, hash[:], signature)
	if err != nil {
		return fmt.Errorf("hardware verification failed: %w", err)
	}

	if !valid {
		return fmt.Errorf("signature verification failed: signature does not match")
	}

	return nil
}

// VerifyManifestHash verifies that a manifest hash matches the expected value
//
// This provides an additional check beyond signature verification.
// The manifest hash should be included in the attestation UserData.
func (v *MinimalVerifier) VerifyManifestHash(
	manifest []byte,
	expectedHash []byte,
) error {
	// Compute SHA256 hash of manifest
	hash := sha256.Sum256(manifest)

	// Compare with expected
	if len(expectedHash) != 32 {
		return fmt.Errorf("invalid expected hash length: got %d bytes", len(expectedHash))
	}

	// Constant-time comparison to prevent timing attacks
	equal := true
	for i := 0; i < 32; i++ {
		if hash[i] != expectedHash[i] {
			equal = false
		}
	}

	if !equal {
		return fmt.Errorf("manifest hash mismatch")
	}

	return nil
}

// Close releases resources associated with the verifier
func (v *MinimalVerifier) Close() error {
	if v.device != nil {
		return v.device.Close()
	}
	return nil
}

// GetDeviceInfo returns information about the connected Tropic Square device
func (v *MinimalVerifier) GetDeviceInfo() (*DeviceInfo, error) {
	return v.device.GetInfo()
}
