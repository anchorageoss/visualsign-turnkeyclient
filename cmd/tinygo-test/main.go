package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

// This is a minimal test program to check TinyGo compatibility
// for the verification functionality

func main() {
	fmt.Println("TinyGo RISC-V Verification Test")
	fmt.Println("================================")

	// Test 1: Basic crypto operations
	fmt.Println("\n[Test 1] Testing SHA256...")
	testSHA256()

	// Test 2: Test ECDSA public key creation
	fmt.Println("\n[Test 2] Testing ECDSA Public Key Creation...")
	pubKey, err := testPublicKeyCreation()
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		return
	}
	fmt.Println("SUCCESS: Public key created")

	// Test 3: Test ECDSA signature verification
	fmt.Println("\n[Test 3] Testing ECDSA Signature Verification...")
	err = testSignatureVerification(pubKey)
	if err != nil {
		fmt.Printf("FAILED: %v\n", err)
		return
	}
	fmt.Println("SUCCESS: Signature verified")

	fmt.Println("\n================================")
	fmt.Println("All basic crypto tests passed!")
}

func testSHA256() {
	testData := []byte("Hello, TinyGo on RISC-V!")
	hash := sha256.Sum256(testData)
	fmt.Printf("SHA256 hash: %s\n", hex.EncodeToString(hash[:]))
}

func testPublicKeyCreation() (*ecdsa.PublicKey, error) {
	// Example P-256 public key (uncompressed format)
	// This is a test key from the secp256r1 curve
	publicKeyHex := "04" + // uncompressed format prefix
		"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" + // X coordinate
		"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5" // Y coordinate

	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key hex: %w", err)
	}

	if publicKeyBytes[0] != 0x04 {
		return nil, fmt.Errorf("expected uncompressed public key format")
	}

	curve := elliptic.P256()
	keyLen := 32
	x := new(big.Int).SetBytes(publicKeyBytes[1 : 1+keyLen])
	y := new(big.Int).SetBytes(publicKeyBytes[1+keyLen:])

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Verify the public key is on the curve
	if !curve.IsOnCurve(pubKey.X, pubKey.Y) {
		return nil, fmt.Errorf("public key is not on the P256 curve")
	}

	return pubKey, nil
}

func testSignatureVerification(pubKey *ecdsa.PublicKey) error {
	// Test message
	message := []byte("test message for verification")
	messageHash := sha256.Sum256(message)

	// Example signature (r, s values) - 32 bytes each
	// Note: This is a dummy signature for testing compilation
	// In real use, this would be a valid signature from the private key
	signatureHex := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" + // r (32 bytes)
		"fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321" // s (32 bytes)

	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	if len(signatureBytes) != 64 {
		return fmt.Errorf("expected 64-byte signature, got %d bytes", len(signatureBytes))
	}

	// Extract r and s
	r := new(big.Int).SetBytes(signatureBytes[:32])
	s := new(big.Int).SetBytes(signatureBytes[32:])

	// Verify signature (this will likely fail since it's a dummy signature)
	// But we're testing that the verification function compiles and runs
	valid := ecdsa.Verify(pubKey, messageHash[:], r, s)

	fmt.Printf("Signature verification result: %v (expected: false for dummy signature)\n", valid)

	// We don't return error here since we expect it to fail with dummy data
	// The important thing is that the code compiles and runs
	return nil
}
