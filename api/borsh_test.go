package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
)

func strPtr(s string) *string       { return &s }
func abiTypePtr(t AbiType) *AbiType { return &t }

// TestMetadataDigestHex_Fixture pins the Go Borsh encoding against a known digest
// computed by the Rust visualsign-parser. To regenerate after a schema change:
// in visualsign-parser, write a small Rust program that calls
// borsh::to_vec(&ChainMetadata{...}) + sha256, with the same input as below.
func TestMetadataDigestHex_Fixture(t *testing.T) {
	// Input matches the Rust parser dump exactly:
	//   network_id = "ETHEREUM_MAINNET"
	//   abi_mappings = {"0xContract": Abi{value: `[{"name":"transfer"}]`,
	//                   signature: None, abi_type: None, implementation_address: None}}
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
	require.Equal(t, "83f5cb4a471503d63778df7fffc8b6c1fd34126f876ef81e33aee3c556129091", digest,
		"Borsh encoding diverged from Rust parser — update fixture or fix encoding")
}

// TestMetadataDigestHex_NilReceiverDoesNotPanic verifies that calling MetadataDigestHex
// on a nil *RequestChainMetadata does not panic and returns the Borsh encoding of
// ChainMetadata{metadata:None}, which is sha256([0x00]). This differs from
// emptyMetadataDigestHex (sha256("")) — the nil receiver path is a Go safety guard,
// not a match for the backend's no-metadata-sent digest.
func TestMetadataDigestHex_NilReceiverDoesNotPanic(t *testing.T) {
	var r *RequestChainMetadata
	digest, err := r.MetadataDigestHex()
	require.NoError(t, err)
	// sha256([0x00]) — Borsh Option::None encoding, NOT sha256("")
	require.Equal(t, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", digest)
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

// TestBorshBytes_MatchesDigest verifies that SHA256(BorshBytes()) equals
// MetadataDigestHex() for the same input — they share the underlying
// borsh::to_vec call and must stay in lockstep.
func TestBorshBytes_MatchesDigest(t *testing.T) {
	meta := &RequestChainMetadata{
		Ethereum: &EthereumChainMetadata{
			NetworkID: strPtr("ETHEREUM_MAINNET"),
			ABIMappings: map[string]ABIValue{
				"0xContract": {Value: `[{"name":"transfer"}]`},
			},
		},
	}
	bytes, err := meta.BorshBytes()
	require.NoError(t, err)
	require.NotEmpty(t, bytes)

	digestFromBytes := manifest.ComputeHash(bytes)
	digestFromHelper, err := meta.MetadataDigestHex()
	require.NoError(t, err)
	require.Equal(t, digestFromHelper, digestFromBytes,
		"SHA256(BorshBytes()) must equal MetadataDigestHex()")
}

// TestMetadataDigestHex_AbiTypeAndImplAddress verifies the new Abi fields are
// included in the digest and that nil (proto None) differs from an explicit
// AbiTypeUnspecified (proto Some(0)) — they encode as distinct Borsh bytes.
func TestMetadataDigestHex_AbiTypeAndImplAddress(t *testing.T) {
	base := func(v ABIValue) *RequestChainMetadata {
		return &RequestChainMetadata{
			Ethereum: &EthereumChainMetadata{
				ABIMappings: map[string]ABIValue{"0xContract": v},
			},
		}
	}

	none, err := base(ABIValue{Value: `[{"name":"transfer"}]`}).MetadataDigestHex()
	require.NoError(t, err)

	// Explicit Unspecified is Some(0), not None — must differ from nil.
	unspecified, err := base(ABIValue{
		Value:   `[{"name":"transfer"}]`,
		AbiType: abiTypePtr(AbiTypeUnspecified),
	}).MetadataDigestHex()
	require.NoError(t, err)
	require.NotEqual(t, none, unspecified, "nil AbiType (None) must differ from explicit Unspecified (Some(0))")

	// Proxy with an implementation address differs from the no-type case.
	proxy, err := base(ABIValue{
		Value:                 `[{"name":"transfer"}]`,
		AbiType:               abiTypePtr(AbiTypeProxy),
		ImplementationAddress: strPtr("0x1111111111111111111111111111111111111111"),
	}).MetadataDigestHex()
	require.NoError(t, err)
	require.NotEqual(t, none, proxy)
	require.NotEqual(t, unspecified, proxy)
}

// TestMetadataDigestHex_UnknownAbiType verifies an unrecognized AbiType string is
// a hard error rather than a silently-wrong digest.
func TestMetadataDigestHex_UnknownAbiType(t *testing.T) {
	meta := &RequestChainMetadata{
		Ethereum: &EthereumChainMetadata{
			ABIMappings: map[string]ABIValue{
				"0xContract": {Value: `[]`, AbiType: abiTypePtr(AbiType("ABI_TYPE_BOGUS"))},
			},
		},
	}
	_, err := meta.MetadataDigestHex()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown abi_type")
}

// TestBorshBytes_NilReceiver returns the Borsh encoding of
// ChainMetadata{metadata: None} (= []byte{0x00}) without panicking.
func TestBorshBytes_NilReceiver(t *testing.T) {
	var r *RequestChainMetadata
	bytes, err := r.BorshBytes()
	require.NoError(t, err)
	require.Equal(t, []byte{0x00}, bytes,
		"nil receiver must Borsh-encode as ChainMetadata{metadata: None} ([0x00])")
}
