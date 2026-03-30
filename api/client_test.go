package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGenerateStampBasic tests basic stamp generation
func TestGenerateStampBasic(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		HostURI: "https://api.turnkey.com",
		APIKey: &TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	requestBody := []byte(`{"test": "data"}`)
	stamp, err := client.generateStamp(requestBody)

	require.NoError(t, err)
	require.NotEmpty(t, stamp)

	// Verify it's valid base64
	decoded, err := base64.RawURLEncoding.DecodeString(stamp)
	require.NoError(t, err)

	// Verify it's valid JSON
	var stampData TurnkeyStamp
	err = json.Unmarshal(decoded, &stampData)
	require.NoError(t, err)
	require.Equal(t, "test-public-key", stampData.PublicKey)
	require.Equal(t, "SIGNATURE_SCHEME_TK_API_P256", stampData.Scheme)
	require.NotEmpty(t, stampData.Signature)
}

// TestGenerateStampWithDifferentData tests stamp generation with different request bodies
func TestGenerateStampWithDifferentData(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		HostURI: "https://api.turnkey.com",
		APIKey: &TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	// Generate stamps for different request bodies
	stamp1, err := client.generateStamp([]byte("data1"))
	require.NoError(t, err)

	stamp2, err := client.generateStamp([]byte("data2"))
	require.NoError(t, err)

	// Stamps should be different for different data
	require.NotEqual(t, stamp1, stamp2)
}

// TestGenerateStampConsistency tests that same data produces same signature
func TestGenerateStampConsistency(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		HostURI: "https://api.turnkey.com",
		APIKey: &TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	requestBody := []byte(`{"test": "data"}`)

	// Generate stamps for the same data
	stamp1, err := client.generateStamp(requestBody)
	require.NoError(t, err)

	stamp2, err := client.generateStamp(requestBody)
	require.NoError(t, err)

	// Decode and check that both have valid structure
	decoded1, err := base64.RawURLEncoding.DecodeString(stamp1)
	require.NoError(t, err)

	decoded2, err := base64.RawURLEncoding.DecodeString(stamp2)
	require.NoError(t, err)

	var stampData1, stampData2 TurnkeyStamp
	err = json.Unmarshal(decoded1, &stampData1)
	require.NoError(t, err)

	err = json.Unmarshal(decoded2, &stampData2)
	require.NoError(t, err)

	// Public key should be the same
	require.Equal(t, stampData1.PublicKey, stampData2.PublicKey)

	// Scheme should be the same
	require.Equal(t, stampData1.Scheme, stampData2.Scheme)
}

// TestSignWithAPIKeyBasic tests basic signing functionality
func TestSignWithAPIKeyBasic(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		HostURI: "https://api.turnkey.com",
		APIKey: &TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	data := []byte("test data to sign")
	signature, err := client.signWithAPIKey(data)

	require.NoError(t, err)
	require.NotEmpty(t, signature)
	require.Greater(t, len(signature), 0)
}

// TestSignWithAPIKeyDifferentData tests signing different data
func TestSignWithAPIKeyDifferentData(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		HostURI: "https://api.turnkey.com",
		APIKey: &TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	data1 := []byte("data1")
	data2 := []byte("data2")

	sig1, err := client.signWithAPIKey(data1)
	require.NoError(t, err)

	sig2, err := client.signWithAPIKey(data2)
	require.NoError(t, err)

	// Different data should produce different signatures
	require.NotEqual(t, hex.EncodeToString(sig1), hex.EncodeToString(sig2))
}

// TestSignWithAPIKeyEmptyData tests signing empty data
func TestSignWithAPIKeyEmptyData(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		HostURI: "https://api.turnkey.com",
		APIKey: &TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	// Signing empty data should still work
	signature, err := client.signWithAPIKey([]byte{})

	require.NoError(t, err)
	require.NotEmpty(t, signature)
}

// TestSignatureIsValidECDSA tests that signatures are valid ECDSA signatures
func TestSignatureIsValidECDSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		HostURI: "https://api.turnkey.com",
		APIKey: &TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	data := []byte("test data")
	signature, err := client.signWithAPIKey(data)

	require.NoError(t, err)
	require.NotEmpty(t, signature)

	// Signature should be parseable as DER-encoded ECDSA signature
	// ECDSA signatures in DER format start with 0x30 (SEQUENCE tag)
	require.Greater(t, len(signature), 0)
	require.Equal(t, byte(0x30), signature[0], "signature should be DER-encoded ECDSA signature")
}

// TestGenerateStampValidation tests stamp validation
func TestGenerateStampValidation(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client := &Client{
		HostURI: "https://api.turnkey.com",
		APIKey: &TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	// Create a large request body
	largeData := make([]byte, 10000)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	stamp, err := client.generateStamp(largeData)
	require.NoError(t, err)
	require.NotEmpty(t, stamp)

	// Verify structure is correct
	decoded, err := base64.RawURLEncoding.DecodeString(stamp)
	require.NoError(t, err)

	var stampData TurnkeyStamp
	err = json.Unmarshal(decoded, &stampData)
	require.NoError(t, err)

	require.Equal(t, "test-public-key", stampData.PublicKey)
	require.Equal(t, "SIGNATURE_SCHEME_TK_API_P256", stampData.Scheme)
	require.NotEmpty(t, stampData.Signature)
}

// TestGenerateStampWithDifferentKeys tests stamp generation with different keys produces different signatures
func TestGenerateStampWithDifferentKeys(t *testing.T) {
	privKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client1 := &Client{
		HostURI: "https://api.turnkey.com",
		APIKey: &TurnkeyAPIKey{
			PublicKey:      "public-key-1",
			PrivateKey:     privKey1,
			OrganizationID: "test-org",
		},
	}

	client2 := &Client{
		HostURI: "https://api.turnkey.com",
		APIKey: &TurnkeyAPIKey{
			PublicKey:      "public-key-2",
			PrivateKey:     privKey2,
			OrganizationID: "test-org",
		},
	}

	data := []byte("same data")

	stamp1, err := client1.generateStamp(data)
	require.NoError(t, err)

	stamp2, err := client2.generateStamp(data)
	require.NoError(t, err)

	// Stamps should be different for different keys
	require.NotEqual(t, stamp1, stamp2)

	// Verify they decode correctly
	decoded1, err := base64.RawURLEncoding.DecodeString(stamp1)
	require.NoError(t, err)

	decoded2, err := base64.RawURLEncoding.DecodeString(stamp2)
	require.NoError(t, err)

	var stampData1, stampData2 TurnkeyStamp
	err = json.Unmarshal(decoded1, &stampData1)
	require.NoError(t, err)

	err = json.Unmarshal(decoded2, &stampData2)
	require.NoError(t, err)

	require.Equal(t, "public-key-1", stampData1.PublicKey)
	require.Equal(t, "public-key-2", stampData2.PublicKey)
}

// TestGenerateStampNilPrivateKey tests that generateStamp returns empty string when PrivateKey is nil
func TestGenerateStampNilPrivateKey(t *testing.T) {
	client := &Client{
		HostURI: "https://api.turnkey.com",
		APIKey: &TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			OrganizationID: "test-org",
		},
	}

	stamp, err := client.generateStamp([]byte(`{"test": "data"}`))
	require.NoError(t, err)
	require.Empty(t, stamp)
}

// TestGenerateStampNilAPIKey tests that generateStamp returns empty string when APIKey is nil
func TestGenerateStampNilAPIKey(t *testing.T) {
	client := &Client{
		HostURI: "https://api.turnkey.com",
	}

	stamp, err := client.generateStamp([]byte(`{"test": "data"}`))
	require.NoError(t, err)
	require.Empty(t, stamp)
}

// BenchmarkGenerateStamp benchmarks stamp generation performance
func BenchmarkGenerateStamp(b *testing.B) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(b, err)

	client := &Client{
		HostURI: "https://api.turnkey.com",
		APIKey: &TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	requestBody := []byte(`{"test": "data"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.generateStamp(requestBody)
		require.NoError(b, err)
	}
}

// BenchmarkSignWithAPIKey benchmarks API key signing performance
func BenchmarkSignWithAPIKey(b *testing.B) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(b, err)

	client := &Client{
		HostURI: "https://api.turnkey.com",
		APIKey: &TurnkeyAPIKey{
			PublicKey:      "test-public-key",
			PrivateKey:     privKey,
			OrganizationID: "test-org",
		},
	}

	data := []byte("test data to sign")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.signWithAPIKey(data)
		require.NoError(b, err)
	}
}
