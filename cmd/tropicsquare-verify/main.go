// Package main provides a command-line tool for verifying attestations
// using Tropic Square TROPIC01 hardware acceleration.
//
// This is currently a skeleton implementation waiting for libtropic SDK integration.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/anchorageoss/visualsign-turnkeyclient/pkg/tropicsquare"
)

var (
	publicKeyHex = flag.String("pubkey", "", "Public key in hex (65 bytes, uncompressed P-256)")
	messageHex   = flag.String("message", "", "Message in hex")
	signatureHex = flag.String("signature", "", "Signature in hex (64 bytes, r||s)")
	deviceInfo   = flag.Bool("info", false, "Show device information and exit")
)

func main() {
	flag.Parse()

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Initialize Tropic Square device
	verifier, err := tropicsquare.NewMinimalVerifier()
	if err != nil {
		return fmt.Errorf("failed to initialize Tropic Square device: %w", err)
	}
	defer verifier.Close()

	// If info flag is set, just show device info and exit
	if *deviceInfo {
		return showDeviceInfo(verifier)
	}

	// Validate required flags
	if *publicKeyHex == "" || *messageHex == "" || *signatureHex == "" {
		return fmt.Errorf("all flags are required: -pubkey, -message, -signature\nUse -h for help")
	}

	// Decode inputs
	publicKey, err := hex.DecodeString(*publicKeyHex)
	if err != nil {
		return fmt.Errorf("invalid public key hex: %w", err)
	}

	message, err := hex.DecodeString(*messageHex)
	if err != nil {
		return fmt.Errorf("invalid message hex: %w", err)
	}

	signature, err := hex.DecodeString(*signatureHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	// Verify attestation using hardware
	fmt.Println("Verifying attestation with Tropic Square hardware...")
	err = verifier.VerifyAttestation(publicKey, message, signature)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	fmt.Println("✓ Verification successful!")
	return nil
}

func showDeviceInfo(verifier *tropicsquare.MinimalVerifier) error {
	info, err := verifier.GetDeviceInfo()
	if err != nil {
		return fmt.Errorf("failed to get device info: %w", err)
	}

	fmt.Println("Tropic Square Device Information:")
	fmt.Printf("  Chip ID:          %s\n", info.ChipID)
	fmt.Printf("  Firmware Version: %s\n", info.FirmwareVersion)
	fmt.Printf("  SPECT Version:    %s\n", info.SPECTVersion)
	if info.PartNumber != "" {
		fmt.Printf("  Part Number:      %s\n", info.PartNumber)
	}

	return nil
}
