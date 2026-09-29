package api

import (
	"encoding/hex"
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

func originChainPtr(c TokenOriginChain) *TokenOriginChain { return &c }

// nearFixture is the input the Rust ground-truth test builds. Kept beside the
// expected bytes so the two cannot drift apart silently.
func nearFixture() *RequestChainMetadata {
	return &RequestChainMetadata{
		Near: &NearChainMetadata{
			NetworkID: strPtr("NEAR_TESTNET"),
			TokenMappings: map[string]TokenMetadataEntry{
				// Declared out of key order: Rust's BTreeMap encodes ascending,
				// and reproducing that with an explicit sort is what is pinned.
				"nep141:zzz.near": {
					Value: `{"symbol":"ZZZ","decimals":8}`,
				},
				"nep141:wrap.near": {
					Value: `{"symbol":"wNEAR","decimals":24}`,
					Signature: NewABISignature(
						"deadbeef", "ed25519", "abc123",
					),
					OriginChain: originChainPtr(TokenOriginChainEthereum),
				},
			},
		},
	}
}

// TestBorshBytes_NearFixture pins the Go encoding against bytes produced by the
// Rust parser's own generated types, not against a digest this package computed
// for itself. Bytes rather than a digest because a mismatch then says where the
// encodings diverge instead of only that they did.
//
// To regenerate after a schema change: in visualsign-parser, run the test at
// src/generated/tests/near_metadata_borsh_truth.rs, which prints
// hex(borsh::to_vec(&ChainMetadata{..})) for these same two inputs.
func TestBorshBytes_NearFixture(t *testing.T) {
	t.Run("network only", func(t *testing.T) {
		meta := &RequestChainMetadata{
			Near: &NearChainMetadata{NetworkID: strPtr("NEAR_MAINNET")},
		}
		b, err := meta.BorshBytes()
		require.NoError(t, err)
		require.Equal(t, "0102010c0000004e4541525f4d41494e4e455400000000", hex.EncodeToString(b),
			"Borsh encoding diverged from the Rust parser")
	})

	t.Run("token mappings, sorted and signed", func(t *testing.T) {
		b, err := nearFixture().BorshBytes()
		require.NoError(t, err)
		require.Equal(t,
			"0102010c0000004e4541525f544553544e455402000000100000006e65703134313a777261702e6e656172"+
				"200000007b2273796d626f6c223a22774e454152222c22646563696d616c73223a32347d0108000000"+
				"64656164626565660200000009000000616c676f726974686d07000000656432353531390a00000070"+
				"75626c69635f6b65790600000061626331323301020000000f0000006e65703134313a7a7a7a2e6e65"+
				"61721d0000007b2273796d626f6c223a225a5a5a222c22646563696d616c73223a387d0000",
			hex.EncodeToString(b),
			"Borsh encoding diverged from the Rust parser")
	})
}

// TestBorshBytes_NearIsDeterministicAcrossMapOrder guards the one hazard Go's
// randomized map iteration introduces: the same mappings must encode identically
// every time, or the digest a verifier recomputes would not be reproducible.
func TestBorshBytes_NearIsDeterministicAcrossMapOrder(t *testing.T) {
	first, err := nearFixture().BorshBytes()
	require.NoError(t, err)
	for range 32 {
		again, err := nearFixture().BorshBytes()
		require.NoError(t, err)
		require.Equal(t, first, again, "token_mappings must encode in ascending key order every time")
	}
}

// TestBorshBytes_NearRejectsAnUnknownOriginChain asserts the posture
// toBorshAbiType already takes: an unrecognized enum value fails the call
// rather than encoding a number the parser would not agree with.
func TestBorshBytes_NearRejectsAnUnknownOriginChain(t *testing.T) {
	meta := &RequestChainMetadata{
		Near: &NearChainMetadata{
			TokenMappings: map[string]TokenMetadataEntry{
				"nep141:wrap.near": {
					Value:       `{"symbol":"wNEAR","decimals":24}`,
					OriginChain: originChainPtr("TOKEN_ORIGIN_CHAIN_MOON"),
				},
			},
		},
	}
	_, err := meta.BorshBytes()
	require.ErrorContains(t, err, "unknown origin_chain")
	require.ErrorContains(t, err, "nep141:wrap.near", "the error must name the entry at fault")
}

// TestBorshBytes_RejectsMoreThanOneVariant covers the three-variant form of the
// invariant: a value with two variants set has no single chain discriminator,
// so it must fail rather than silently encode whichever the switch reaches first.
func TestBorshBytes_RejectsMoreThanOneVariant(t *testing.T) {
	meta := &RequestChainMetadata{
		Ethereum: &EthereumChainMetadata{},
		Near:     &NearChainMetadata{},
	}
	_, err := meta.BorshBytes()
	require.ErrorContains(t, err, "exactly one variant")
	require.ErrorContains(t, err, "Ethereum")
	require.ErrorContains(t, err, "Near")
}
