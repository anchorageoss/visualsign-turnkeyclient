// Package main implements a hardware wallet verifier for RISC-V
//
// This runs on a RISC-V sidecar board and communicates with TROPIC01
// secure element for signing operations. It handles:
// - Transaction display and confirmation
// - Signature verification (using pure Go crypto)
// - Attestation validation
// - User interface
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/anchorageoss/visualsign-turnkeyclient/pkg/tropicsquare"
)

func main() {
	fmt.Println("Hardware Wallet - RISC-V Verifier")
	fmt.Println("==================================")

	// Initialize verifier (pure Go, no hardware needed)
	verifier, err := tropicsquare.NewMinimalVerifier()
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize verifier: %v", err))
	}
	defer verifier.Close()

	// Initialize communication with TROPIC01
	signer := NewTROPIC01Signer("/dev/spidev0.0") // Or UART
	if err := signer.Init(); err != nil {
		panic(fmt.Sprintf("Failed to connect to TROPIC01: %v", err))
	}
	defer signer.Close()

	// Get device info from TROPIC01
	info, err := signer.GetDeviceInfo()
	if err != nil {
		panic(fmt.Sprintf("Failed to get device info: %v", err))
	}
	fmt.Printf("Connected to TROPIC01: %s\n", info.ChipID)
	fmt.Printf("Firmware: %s\n\n", info.FirmwareVersion)

	// Example: Sign and verify a transaction
	if err := signAndVerifyTransaction(signer, verifier); err != nil {
		panic(fmt.Sprintf("Transaction failed: %v", err))
	}

	fmt.Println("\n✓ All operations completed successfully!")
}

// signAndVerifyTransaction demonstrates the full flow:
// 1. Display transaction to user
// 2. Request signature from TROPIC01
// 3. Verify signature locally
// 4. Confirm with user
func signAndVerifyTransaction(signer *TROPIC01Signer, verifier *tropicsquare.MinimalVerifier) error {
	// Example transaction
	tx := Transaction{
		To:     "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
		Amount: "1.5",
		Token:  "ETH",
		Nonce:  12345,
	}

	fmt.Println("Transaction to sign:")
	fmt.Printf("  To:     %s\n", tx.To)
	fmt.Printf("  Amount: %s %s\n", tx.Amount, tx.Token)
	fmt.Printf("  Nonce:  %d\n", tx.Nonce)
	fmt.Println()

	// Compute transaction hash
	txData := tx.Serialize()
	txHash := sha256.Sum256(txData)
	fmt.Printf("Transaction hash: %s\n", hex.EncodeToString(txHash[:]))

	// Request signature from TROPIC01
	// This uses hardware signing with keys stored in secure element
	fmt.Println("\nRequesting signature from TROPIC01...")
	sigResponse, err := signer.Sign(0, txHash[:]) // Key slot 0
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	fmt.Printf("Signature received:\n")
	fmt.Printf("  R: %s\n", hex.EncodeToString(sigResponse.Signature[:32]))
	fmt.Printf("  S: %s\n", hex.EncodeToString(sigResponse.Signature[32:]))

	// Verify signature locally on RISC-V
	// This uses pure Go crypto/ecdsa (no hardware needed)
	fmt.Println("\nVerifying signature locally...")
	err = verifier.VerifyAttestation(
		sigResponse.PublicKey, // Public key from TROPIC01
		txHash[:],             // Transaction hash
		sigResponse.Signature,  // Signature from TROPIC01
	)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	fmt.Println("✓ Signature verified!")

	// In a real wallet, you would:
	// 1. Display transaction details on screen
	// 2. Wait for user confirmation (button press)
	// 3. Broadcast signed transaction
	fmt.Println("\n[Press button to confirm broadcast]")
	// waitForUserConfirmation()

	fmt.Println("✓ Transaction would be broadcast")
	return nil
}

// Transaction represents a transaction to sign
type Transaction struct {
	To     string
	Amount string
	Token  string
	Nonce  uint64
}

// Serialize converts transaction to bytes for hashing
func (t *Transaction) Serialize() []byte {
	// Simplified serialization
	// Real implementation would use proper encoding (RLP for Ethereum, etc.)
	s := fmt.Sprintf("%s:%s:%s:%d", t.To, t.Amount, t.Token, t.Nonce)
	return []byte(s)
}
