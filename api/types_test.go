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
