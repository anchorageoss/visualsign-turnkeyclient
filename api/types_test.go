package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestABIValue_JSONWireFormat pins the JSON contract the parser receives. The
// metadata digest hashes the proto enum number (see borsh_test.go), but the
// value sent over the wire is the proto enum name, matching the parser's serde.
// This test guards the string contract independently of the borsh number map, so
// a typo'd AbiType constant cannot pass silently.
func TestABIValue_JSONWireFormat(t *testing.T) {
	v := ABIValue{
		Value:                 `[{"name":"transfer"}]`,
		AbiType:               abiTypePtr(AbiTypeProxy),
		ImplementationAddress: strPtr("0x1111111111111111111111111111111111111111"),
	}

	b, err := json.Marshal(v)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	require.Equal(t, `[{"name":"transfer"}]`, m["value"])
	require.Equal(t, "ABI_TYPE_PROXY", m["abiType"], "abi_type must serialize as the proto enum name")
	require.Equal(t, "0x1111111111111111111111111111111111111111", m["implementationAddress"])

	// Round-trips back to the same struct.
	var back ABIValue
	require.NoError(t, json.Unmarshal(b, &back))
	require.Equal(t, v, back)
}

// TestAbiTypeConstants_ProtoNames pins each constant's wire string to its proto
// enum name. The borsh number map keys off these values, so a typo here would
// otherwise pass the digest tests while corrupting the wire contract.
func TestAbiTypeConstants_ProtoNames(t *testing.T) {
	require.Equal(t, AbiType("ABI_TYPE_UNSPECIFIED"), AbiTypeUnspecified)
	require.Equal(t, AbiType("ABI_TYPE_IMPLEMENTATION"), AbiTypeImplementation)
	require.Equal(t, AbiType("ABI_TYPE_PROXY"), AbiTypeProxy)
}

// TestABIValue_JSONOmitsNilFields verifies the new optional fields are omitted
// when unset, so existing requests keep the same wire shape (and the parser sees
// proto None, not Some(default)).
func TestABIValue_JSONOmitsNilFields(t *testing.T) {
	b, err := json.Marshal(ABIValue{Value: "[]"})
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	require.Contains(t, m, "value")
	require.NotContains(t, m, "abiType")
	require.NotContains(t, m, "implementationAddress")
	require.NotContains(t, m, "signature")
}

// TestRequestChainMetadata_JSONRoundTrip pins the gateway's internally-tagged
// wire shape ({"chain": "CHAIN_...", ...fields...}) in both directions.
// UnmarshalJSON exists solely to parse cmd/verify.go's --chain-metadata flag
// value; without it, a caller-supplied JSON string silently produces an empty
// RequestChainMetadata (see the "must" review comment on api/types.go).
func TestRequestChainMetadata_JSONRoundTrip(t *testing.T) {
	t.Run("ethereum", func(t *testing.T) {
		networkID := "1"
		original := RequestChainMetadata{
			Ethereum: &EthereumChainMetadata{
				NetworkID: &networkID,
				ABIMappings: map[string]ABIValue{
					"0xContractAddr": {Value: `[{"name":"transfer"}]`},
				},
			},
		}

		b, err := json.Marshal(original)
		require.NoError(t, err)

		var m map[string]any
		require.NoError(t, json.Unmarshal(b, &m))
		require.Equal(t, "CHAIN_ETHEREUM", m["chain"])

		var back RequestChainMetadata
		require.NoError(t, json.Unmarshal(b, &back))
		require.Equal(t, original, back)
	})

	t.Run("solana", func(t *testing.T) {
		original := RequestChainMetadata{
			Solana: &SolanaChainMetadata{
				SimulatedTransactionResult: []byte("raw-simulate-transaction-bytes"),
			},
		}

		b, err := json.Marshal(original)
		require.NoError(t, err)

		var m map[string]any
		require.NoError(t, json.Unmarshal(b, &m))
		require.Equal(t, "CHAIN_SOLANA", m["chain"])

		var back RequestChainMetadata
		require.NoError(t, json.Unmarshal(b, &back))
		require.Equal(t, original, back)
	})

	t.Run("unmarshal rejects missing chain discriminator", func(t *testing.T) {
		var m RequestChainMetadata
		err := json.Unmarshal([]byte(`{"networkId":"1"}`), &m)
		require.Error(t, err)
	})

	t.Run("unmarshal rejects unknown chain discriminator", func(t *testing.T) {
		var m RequestChainMetadata
		err := json.Unmarshal([]byte(`{"chain":"CHAIN_NEAR"}`), &m)
		require.Error(t, err)
	})

	t.Run("marshal rejects both variants set", func(t *testing.T) {
		m := RequestChainMetadata{
			Ethereum: &EthereumChainMetadata{},
			Solana:   &SolanaChainMetadata{},
		}
		_, err := json.Marshal(m)
		require.Error(t, err)
	})

	t.Run("marshal rejects neither variant set", func(t *testing.T) {
		_, err := json.Marshal(RequestChainMetadata{})
		require.Error(t, err)
	})
}
