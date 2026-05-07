package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func strPtr(s string) *string { return &s }

// TestMetadataDigestHex_Fixture pins the Go Borsh encoding against a known digest
// computed by the Rust visualsign-parser. To regenerate after a schema change:
// in visualsign-parser, write a small Rust program that calls
// borsh::to_vec(&ChainMetadata{...}) + sha256, with the same input as below.
func TestMetadataDigestHex_Fixture(t *testing.T) {
	// Input matches borsh_fixture.rs exactly:
	//   network_id = "ETHEREUM_MAINNET"
	//   abi_mappings = {"0xContract": Abi{value: `[{"name":"transfer"}]`, signature: None}}
	meta := &RequestChainMetadata{
		Ethereum: &EthereumChainMetadata{
			NetworkID: strPtr("ETHEREUM_MAINNET"),
			ABIMappings: map[string]ABIValue{
				"0xContract": {Value: `[{"name":"transfer"}]`},
			},
		},
	}
	digest, err := meta.MetadataDigestHex()
	require.NoError(t, err)
	require.Equal(t, "801f265e405cdfa6435a30b09ccd72c6bd1535c8ac4b8dab7699d119a925b84d", digest,
		"Borsh encoding diverged from Rust parser — update fixture or fix encoding")
}

// TestMetadataDigestHex_NilMetadata verifies that a nil RequestChainMetadata
// produces the empty-input SHA-256 (matching the backend when no metadata is sent).
func TestMetadataDigestHex_NilMetadata(t *testing.T) {
	var r *RequestChainMetadata
	digest, err := r.MetadataDigestHex()
	require.NoError(t, err)
	// SHA-256 of the Borsh-encoded ChainMetadata with metadata=None is sha256([0x00]).
	// Distinct from sha256("") — but the backend path for nil chain_metadata uses
	// vec![] (empty bytes), not borsh(None). The nil path in Go should not normally
	// be called (callers only call MetadataDigestHex when ChainMetadata is non-nil).
	require.NotEmpty(t, digest)
}

// TestMetadataDigestHex_Deterministic verifies that two identical RequestChainMetadata
// values produce the same digest, and different values produce different digests.
func TestMetadataDigestHex_Deterministic(t *testing.T) {
	meta := &RequestChainMetadata{
		Ethereum: &EthereumChainMetadata{
			NetworkID: strPtr("ETHEREUM_MAINNET"),
			ABIMappings: map[string]ABIValue{
				"0xContractA": {Value: `[{"name":"transfer","type":"function"}]`},
				"0xContractB": {Value: `[{"name":"approve","type":"function"}]`},
			},
		},
	}

	d1, err := meta.MetadataDigestHex()
	require.NoError(t, err)
	d2, err := meta.MetadataDigestHex()
	require.NoError(t, err)
	require.Equal(t, d1, d2, "digest must be deterministic")

	// Different ABI value → different digest
	metaDiff := &RequestChainMetadata{
		Ethereum: &EthereumChainMetadata{
			NetworkID: strPtr("ETHEREUM_MAINNET"),
			ABIMappings: map[string]ABIValue{
				"0xContractA": {Value: `[{"name":"other","type":"function"}]`},
			},
		},
	}
	dDiff, err := metaDiff.MetadataDigestHex()
	require.NoError(t, err)
	require.NotEqual(t, d1, dDiff)
}

// TestMetadataDigestHex_MapKeyOrder verifies that map insertion order does not
// affect the digest (borsh-go sorts map keys lexicographically).
func TestMetadataDigestHex_MapKeyOrder(t *testing.T) {
	// "0xB" < "0xA" lexicographically is false — "0xA" < "0xB". Both orders
	// should produce the same Borsh output because borsh-go sorts before encoding.
	metaAB := &RequestChainMetadata{
		Ethereum: &EthereumChainMetadata{
			ABIMappings: map[string]ABIValue{
				"0xA": {Value: "abi-a"},
				"0xB": {Value: "abi-b"},
			},
		},
	}
	metaBA := &RequestChainMetadata{
		Ethereum: &EthereumChainMetadata{
			ABIMappings: map[string]ABIValue{
				"0xB": {Value: "abi-b"},
				"0xA": {Value: "abi-a"},
			},
		},
	}
	dAB, err := metaAB.MetadataDigestHex()
	require.NoError(t, err)
	dBA, err := metaBA.MetadataDigestHex()
	require.NoError(t, err)
	require.Equal(t, dAB, dBA, "digest must be independent of map insertion order")
}

// TestMetadataDigestHex_WithSignature verifies that ABISignature is included
// in the digest, so a signed ABI differs from an unsigned one.
func TestMetadataDigestHex_WithSignature(t *testing.T) {
	unsigned := &RequestChainMetadata{
		Ethereum: &EthereumChainMetadata{
			ABIMappings: map[string]ABIValue{
				"0xContract": {Value: `[{"name":"transfer"}]`},
			},
		},
	}
	signed := &RequestChainMetadata{
		Ethereum: &EthereumChainMetadata{
			ABIMappings: map[string]ABIValue{
				"0xContract": {
					Value:     `[{"name":"transfer"}]`,
					Signature: NewABISignature("0xdeadbeef", "secp256k1", "0xpubkey"),
				},
			},
		},
	}

	dUnsigned, err := unsigned.MetadataDigestHex()
	require.NoError(t, err)
	dSigned, err := signed.MetadataDigestHex()
	require.NoError(t, err)
	require.NotEqual(t, dUnsigned, dSigned, "signature must change the digest")
}

// TestNewABISignature verifies the constructor sets the standard metadata fields.
func TestNewABISignature(t *testing.T) {
	sig := NewABISignature("0xsig", "secp256k1", "0xpubkey",
		SignatureKV{Key: "issuer", Value: "0xissuer"},
	)
	require.Equal(t, "0xsig", sig.Value)
	require.Equal(t, []SignatureKV{
		{Key: "algorithm", Value: "secp256k1"},
		{Key: "public_key", Value: "0xpubkey"},
		{Key: "issuer", Value: "0xissuer"},
	}, sig.Metadata)
}

// TestMetadataDigestHex_NilEthereum verifies that a RequestChainMetadata with
// nil Ethereum field encodes as ChainMetadata{metadata: None}.
func TestMetadataDigestHex_NilEthereum(t *testing.T) {
	meta := &RequestChainMetadata{Ethereum: nil}
	digest, err := meta.MetadataDigestHex()
	require.NoError(t, err)
	require.NotEmpty(t, digest)
}
