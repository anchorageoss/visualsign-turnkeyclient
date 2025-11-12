// +build !cgo

package tropicsquare

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

// Device represents a connection to Tropic Square TROPIC01
// This is the pure Go implementation (no CGo) using standard library crypto
type Device struct {
	initialized bool
}

// NewDevice initializes the device
func NewDevice() (*Device, error) {
	return &Device{
		initialized: true,
	}, nil
}

// VerifyECDSA_P256 verifies an ECDSA P-256 signature using Go's crypto/ecdsa
//
// This is a pure Go implementation that doesn't require libtropic or CGo.
// It provides the same verification functionality using Go's standard library.
//
// Parameters:
//   - publicKey: 64-byte P-256 public key (X || Y, without 0x04 prefix)
//   - hash: 32-byte hash of the message
//   - signature: 64-byte signature (r || s)
//
// Returns:
//   - bool: true if signature is valid
//   - error: any error that occurred
func (d *Device) VerifyECDSA_P256(publicKey []byte, hash []byte, signature []byte) (bool, error) {
	if !d.initialized {
		return false, fmt.Errorf("device not initialized")
	}

	// Validate inputs
	if len(publicKey) != 64 {
		return false, fmt.Errorf("invalid public key length: expected 64 bytes (X||Y), got %d", len(publicKey))
	}
	if len(hash) != 32 {
		return false, fmt.Errorf("invalid hash length: expected 32 bytes, got %d", len(hash))
	}
	if len(signature) != 64 {
		return false, fmt.Errorf("invalid signature length: expected 64 bytes (r||s), got %d", len(signature))
	}

	// Reconstruct P-256 public key from X and Y coordinates
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(publicKey[:32])
	y := new(big.Int).SetBytes(publicKey[32:])

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Verify the public key is on the curve
	if !curve.IsOnCurve(pubKey.X, pubKey.Y) {
		return false, fmt.Errorf("public key is not on the P256 curve")
	}

	// Extract r and s from signature
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	// Verify signature
	valid := ecdsa.Verify(pubKey, hash, r, s)
	return valid, nil
}

// GetInfo returns device information
func (d *Device) GetInfo() (*DeviceInfo, error) {
	if !d.initialized {
		return nil, fmt.Errorf("device not initialized")
	}

	return &DeviceInfo{
		ChipID:          "N/A (pure Go implementation)",
		FirmwareVersion: "crypto/ecdsa",
		SPECTVersion:    "N/A",
		PartNumber:      "software",
	}, nil
}

// Close releases device resources
func (d *Device) Close() error {
	d.initialized = false
	return nil
}
