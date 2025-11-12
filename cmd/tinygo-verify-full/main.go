package main

import (
	"fmt"

	// Try importing the actual verification dependencies
	nitroverifier "github.com/anchorageoss/awsnitroverifier"
	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
	"github.com/anchorageoss/visualsign-turnkeyclient/verify"

	// These are the key third-party dependencies that might cause issues
	"github.com/fxamacker/cbor/v2"
	borsh "github.com/near/borsh-go"
)

// Test importing and using actual verification components

func main() {
	fmt.Println("TinyGo Full Verification Test")
	fmt.Println("================================\n")

	// Test 1: Check if we can create a nitroverifier
	fmt.Println("[Test 1] Testing AWS Nitro Verifier...")
	testNitroVerifier()

	// Test 2: Check if we can use CBOR
	fmt.Println("\n[Test 2] Testing CBOR encoding/decoding...")
	testCBOR()

	// Test 3: Check if we can use Borsh
	fmt.Println("\n[Test 3] Testing Borsh encoding/decoding...")
	testBorsh()

	// Test 4: Check if manifest hashing works
	fmt.Println("\n[Test 4] Testing Manifest hashing...")
	testManifestHash()

	// Test 5: Try using the verify service (without network calls)
	fmt.Println("\n[Test 5] Testing Verify Service types...")
	testVerifyService()

	fmt.Println("\n================================")
	fmt.Println("All tests completed!")
}

func testNitroVerifier() {
	// Test that we can reference the types
	// Actually creating a verifier requires x509 certificates which may not work in TinyGo
	var opts nitroverifier.AWSNitroVerifierOptions
	opts.SkipTimestampCheck = true
	fmt.Printf("SUCCESS: Can reference nitro verifier types (SkipTimestampCheck=%v)\n", opts.SkipTimestampCheck)
}

func testCBOR() {
	// Test CBOR encoding/decoding
	type TestStruct struct {
		Name  string `cbor:"name"`
		Value int    `cbor:"value"`
	}

	original := TestStruct{Name: "test", Value: 42}

	// Try encoding
	encoded, err := cbor.Marshal(original)
	if err != nil {
		fmt.Printf("FAILED: CBOR encoding error: %v\n", err)
		return
	}
	fmt.Printf("SUCCESS: CBOR encoded %d bytes\n", len(encoded))

	// Try decoding
	var decoded TestStruct
	err = cbor.Unmarshal(encoded, &decoded)
	if err != nil {
		fmt.Printf("FAILED: CBOR decoding error: %v\n", err)
		return
	}
	fmt.Printf("SUCCESS: CBOR decoded: %+v\n", decoded)
}

func testBorsh() {
	// Test Borsh encoding/decoding
	type TestData struct {
		Value uint64
	}

	original := TestData{Value: 12345}

	// Try encoding
	encoded, err := borsh.Serialize(original)
	if err != nil {
		fmt.Printf("FAILED: Borsh encoding error: %v\n", err)
		return
	}
	fmt.Printf("SUCCESS: Borsh encoded %d bytes\n", len(encoded))

	// Try decoding
	var decoded TestData
	err = borsh.Deserialize(&decoded, encoded)
	if err != nil {
		fmt.Printf("FAILED: Borsh decoding error: %v\n", err)
		return
	}
	fmt.Printf("SUCCESS: Borsh decoded: %+v\n", decoded)
}

func testManifestHash() {
	// Test manifest hash computation
	testData := []byte("test manifest data")
	hash := manifest.ComputeHash(testData)
	fmt.Printf("SUCCESS: Manifest hash computed: %s\n", hash)
}

func testVerifyService() {
	// Just test that we can reference the types
	// We won't actually call the service since we don't have network/API access

	req := &verify.VerifyRequest{
		UnsignedPayload: "test",
		Chain:           "CHAIN_SOLANA",
	}

	fmt.Printf("SUCCESS: Created VerifyRequest: chain=%s\n", req.Chain)
}
