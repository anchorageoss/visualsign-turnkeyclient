package api

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	borsh "github.com/near/borsh-go"
)

// TestCrosscheckGoVsRustOnDeployedProto pins Go's Borsh against Rust borsh::to_vec
// output for the exact same ChainMetadata struct. Ground truth is borsh::to_vec
// over the parser's ChainMetadata, taken from visualsign-parser HEAD with the
// pending Abi additions applied (abi_type tag 3 as Option<i32>, implementation_address
// tag 4). The "network_id only" bytes match the previously deployed proto exactly
// (no Abi entries, so the new fields add nothing); the ABI cases each gain two
// trailing None bytes (abi_type, implementation_address). Regenerate after any
// further Abi schema change.
func TestCrosscheckGoVsRustOnDeployedProto(t *testing.T) {
	for _, tc := range []struct {
		name       string
		meta       *RequestChainMetadata
		rustBytes  string
		rustDigest string
	}{
		{
			name: "network_id only",
			meta: &RequestChainMetadata{
				Ethereum: &EthereumChainMetadata{NetworkID: strPtr("ETHEREUM_MAINNET")},
			},
			rustBytes:  "01000110000000455448455245554d5f4d41494e4e455400000000",
			rustDigest: "92ae0824d8c5d1399829f75dbb6fafb4d98a68745e4328ee1af601365df374f5",
		},
		{
			name: "network_id + USDC ABI",
			meta: &RequestChainMetadata{
				Ethereum: &EthereumChainMetadata{
					NetworkID: strPtr("ETHEREUM_MAINNET"),
					ABIMappings: map[string]ABIValue{
						"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": {Value: `[{"name":"transfer"}]`},
					},
				},
			},
			rustBytes:  "01000110000000455448455245554d5f4d41494e4e4554010000002a000000307861306238363939316336323138623336633164313964346132653965623063653336303665623438150000005b7b226e616d65223a227472616e73666572227d5d000000",
			rustDigest: "e83b524fe218b401bee0d13231bcf7710d6c0ccf4aae1c241aaa5fcefec39946",
		},
		{
			name: "proxy ABI with abi_type + implementation_address",
			meta: &RequestChainMetadata{
				Ethereum: &EthereumChainMetadata{
					NetworkID: strPtr("ETHEREUM_MAINNET"),
					ABIMappings: map[string]ABIValue{
						"0xproxy": {
							Value:                 `[{"name":"transfer"}]`,
							AbiType:               abiTypePtr(AbiTypeProxy),
							ImplementationAddress: strPtr("0x1111111111111111111111111111111111111111"),
						},
					},
				},
			},
			rustBytes:  "01000110000000455448455245554d5f4d41494e4e45540100000007000000307870726f7879150000005b7b226e616d65223a227472616e73666572227d5d000102000000012a000000307831313131313131313131313131313131313131313131313131313131313131313131313131313131",
			rustDigest: "6a11dc83d52472d470aa4373a826e11f5a1d57ee4f46d8105530a3a389cc9921",
		},
		{
			// Two mappings exercise the sort: Rust serializes the HashMap in
			// lexicographic key order (0xaaaa before 0xbbbb), and Go's
			// sort.Slice in toBorshChainMetadata must match byte-for-byte
			// regardless of Go map iteration order. 0xbbbb also pins
			// AbiTypeImplementation (Some(1) -> 01 01000000).
			name: "two ABIs, sorted, with implementation type",
			meta: &RequestChainMetadata{
				Ethereum: &EthereumChainMetadata{
					NetworkID: strPtr("ETHEREUM_MAINNET"),
					ABIMappings: map[string]ABIValue{
						"0xbbbb": {Value: "[]", AbiType: abiTypePtr(AbiTypeImplementation)},
						"0xaaaa": {Value: "[]"},
					},
				},
			},
			rustBytes:  "01000110000000455448455245554d5f4d41494e4e45540200000006000000307861616161020000005b5d00000006000000307862626262020000005b5d00010100000000",
			rustDigest: "ff3492199922108e52fc05edf2a4ceb2a3f7857982a92ed1770aea3997b68cb5",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cm, err := tc.meta.toBorshChainMetadata()
			if err != nil {
				t.Fatal(err)
			}
			goBytes, err := borsh.Serialize(cm)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(goBytes)
			t.Logf("\n[%s]\n  go:   %s\n  rust: %s\n", tc.name, hex.EncodeToString(goBytes), tc.rustBytes)
			if hex.EncodeToString(goBytes) != tc.rustBytes {
				t.Errorf("byte mismatch")
			}
			if hex.EncodeToString(h[:]) != tc.rustDigest {
				t.Errorf("digest mismatch: go=%s rust=%s", hex.EncodeToString(h[:]), tc.rustDigest)
			}
		})
	}
}

// TestCrosscheckGoVsRustSolana pins Go's Borsh encoding of Solana chain
// metadata against real Rust borsh::to_vec output, the same way
// TestCrosscheckGoVsRustOnDeployedProto does for Ethereum. Ground truth was
// computed by running borsh::to_vec over generated::parser::ChainMetadata
// (Solana variant) from visualsign-parser HEAD. Regenerate after any change
// to SolanaMetadata's field layout.
//
// SolanaChainMetadata exposes no public field for NetworkID, Idl, or
// IdlMappings yet, so the cases here cover the reachable shapes: nothing set,
// and SimulatedTransactionResult set. TestCrosscheckGoVsRustSolanaIdlMappings
// covers the IdlMappings encoding directly.
func TestCrosscheckGoVsRustSolana(t *testing.T) {
	for _, tc := range []struct {
		name       string
		meta       *RequestChainMetadata
		rustBytes  string
		rustDigest string
	}{
		{
			name: "nothing set",
			meta: &RequestChainMetadata{
				Solana: &SolanaChainMetadata{},
			},
			rustBytes:  "010100000000000000",
			rustDigest: "46f8ec5a439c92e1df8299e1a4432a7ee172d8496b5e33e0a35a7b67163371b5",
		},
		{
			name: "simulated_transaction_result only",
			meta: &RequestChainMetadata{
				Solana: &SolanaChainMetadata{
					SimulatedTransactionResult: []byte(`{"foo":"bar"}`),
				},
			},
			rustBytes:  "0101000000000000011400000065794a6d623238694f694a695958496966513d3d",
			rustDigest: "a634909f1ca8a29434f6ae3b1869d27af08ec2376d3e473df3275430d457b2e5",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cm, err := tc.meta.toBorshChainMetadata()
			if err != nil {
				t.Fatal(err)
			}
			goBytes, err := borsh.Serialize(cm)
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(goBytes)
			t.Logf("\n[%s]\n  go:   %s\n  rust: %s\n", tc.name, hex.EncodeToString(goBytes), tc.rustBytes)
			if hex.EncodeToString(goBytes) != tc.rustBytes {
				t.Errorf("byte mismatch")
			}
			if hex.EncodeToString(h[:]) != tc.rustDigest {
				t.Errorf("digest mismatch: go=%s rust=%s", hex.EncodeToString(h[:]), tc.rustDigest)
			}
		})
	}
}

// TestCrosscheckGoVsRustSolanaIdlMappings pins the idl_mappings encoding
// against real Rust borsh::to_vec output. Rust declares idl_mappings as a
// BTreeMap, so the ground truth encodes aaaProgram first even though the probe
// inserted zzzProgram first; sortIdlMappings is what makes Go agree.
func TestCrosscheckGoVsRustSolanaIdlMappings(t *testing.T) {
	const rustBytes = "01010000020000000a00000061616150726f6772616d070000007b2261223a317d01010000000106000000302e33302e3000010b0000004a7570697465724c656e640a0000007a7a7a50726f6772616d070000007b227a223a317d0000000000"

	idlType := int32(1) // SolanaIdlType::Anchor

	// Out of ProgramID order, as a Go map range would yield.
	entries := []borshIdlMappingEntry{
		{ProgramID: "zzzProgram", Idl: borshIdl{Value: `{"z":1}`}},
		{ProgramID: "aaaProgram", Idl: borshIdl{
			Value:       `{"a":1}`,
			IdlType:     &idlType,
			IdlVersion:  strPtr("0.30.0"),
			ProgramName: strPtr("JupiterLend"),
		}},
	}

	goBytes, err := borsh.Serialize(borshChainMetadata{
		Metadata: &borshMetadataEnum{
			Enum:   solanaVariant,
			Solana: borshSolanaMetadata{IdlMappings: sortIdlMappings(entries)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(goBytes); got != rustBytes {
		t.Errorf("byte mismatch:\n go:   %s\n rust: %s", got, rustBytes)
	}
}
