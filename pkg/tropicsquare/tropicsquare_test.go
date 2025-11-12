package tropicsquare

import (
	"encoding/hex"
	"testing"
)

// TestVerifyAttestation tests the attestation verification flow
// Note: This will fail until libtropic SDK is integrated
func TestVerifyAttestation(t *testing.T) {
	t.Skip("Skipping: libtropic SDK not yet integrated")

	verifier, err := NewMinimalVerifier()
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}
	defer verifier.Close()

	// Example P-256 public key (uncompressed format: 0x04 || X || Y)
	publicKeyHex := "04" +
		"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" + // X
		"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5" // Y

	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}

	// Example message
	message := []byte("test message for verification")

	// Example signature (r || s, each 32 bytes)
	// In real use, this would be a valid signature from the private key
	signatureHex := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" + // r
		"fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321" // s

	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		t.Fatalf("Failed to decode signature: %v", err)
	}

	// Verify attestation
	err = verifier.VerifyAttestation(publicKey, message, signature)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
}

// TestVerifyAttestation_InvalidPublicKey tests error handling for invalid public keys
func TestVerifyAttestation_InvalidPublicKey(t *testing.T) {
	t.Skip("Skipping: libtropic SDK not yet integrated")

	verifier, err := NewMinimalVerifier()
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}
	defer verifier.Close()

	tests := []struct {
		name      string
		publicKey []byte
		wantError string
	}{
		{
			name:      "too short",
			publicKey: make([]byte, 64),
			wantError: "invalid public key length",
		},
		{
			name:      "wrong prefix",
			publicKey: append([]byte{0x03}, make([]byte, 64)...),
			wantError: "invalid public key format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifier.VerifyAttestation(tt.publicKey, []byte("message"), make([]byte, 64))
			if err == nil {
				t.Error("Expected error, got nil")
			}
		})
	}
}

// TestVerifyManifestHash tests manifest hash verification
func TestVerifyManifestHash(t *testing.T) {
	t.Skip("Skipping: libtropic SDK not yet integrated")

	verifier, err := NewMinimalVerifier()
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}
	defer verifier.Close()

	manifest := []byte("test manifest data")
	// Pre-computed SHA256 hash of the manifest
	expectedHash, _ := hex.DecodeString("4d967a30111bf29f0eba01c448b375c1629b2fed01cdfcc3aed91f1b57d5dd5e")

	err = verifier.VerifyManifestHash(manifest, expectedHash)
	if err != nil {
		t.Errorf("Manifest hash verification failed: %v", err)
	}
}

// TestGetDeviceInfo tests device information retrieval
func TestGetDeviceInfo(t *testing.T) {
	t.Skip("Skipping: libtropic SDK not yet integrated")

	verifier, err := NewMinimalVerifier()
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}
	defer verifier.Close()

	info, err := verifier.GetDeviceInfo()
	if err != nil {
		t.Fatalf("Failed to get device info: %v", err)
	}

	if info.ChipID == "" {
		t.Error("Expected non-empty chip ID")
	}
	if info.FirmwareVersion == "" {
		t.Error("Expected non-empty firmware version")
	}

	t.Logf("Device Info: ChipID=%s, FW=%s, SPECT=%s",
		info.ChipID, info.FirmwareVersion, info.SPECTVersion)
}

// BenchmarkVerifyAttestation benchmarks hardware verification performance
func BenchmarkVerifyAttestation(b *testing.B) {
	b.Skip("Skipping: libtropic SDK not yet integrated")

	verifier, err := NewMinimalVerifier()
	if err != nil {
		b.Fatalf("Failed to create verifier: %v", err)
	}
	defer verifier.Close()

	publicKey := make([]byte, 65)
	publicKey[0] = 0x04
	message := []byte("benchmark message")
	signature := make([]byte, 64)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = verifier.VerifyAttestation(publicKey, message, signature)
	}
}
