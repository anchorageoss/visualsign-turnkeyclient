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
		{
			// Ground truth from visualsign-parser's own borsh::to_vec over
			// ChainMetadata { metadata: Some(Solana(SolanaMetadata { network_id:
			// None, idl: None, idl_mappings: {}, simulate_transaction_result:
			// Some(SimulateTransactionResult { instructions: [one System Program
			// call] }) })) }. Pins the solanaVariant discriminant (01, second
			// oneof variant) and borshSolanaMetadata's field order (NetworkID,
			// Idl, IdlMappings, SimulateTransactionResult — matching the Rust
			// struct's *declaration* order, not proto tag order: network_id is
			// tag 2, idl is tag 1).
			name: "solana simulate transaction result",
			meta: &RequestChainMetadata{
				Solana: &SolanaChainMetadata{
					SimulateTransactionResult: &SimulateTransactionResult{
						Instructions: []SimulatedInstruction{
							{
								ProgramKey:         "11111111111111111111111111111111",
								InstructionDataHex: "0200000001000000000000000000",
							},
						},
					},
				},
			},
			rustBytes:  "010100000000000001010000002000000031313131313131313131313131313131313131313131313131313131313131311c00000030323030303030303031303030303030303030303030303030303030",
			rustDigest: "35340417e7780cdf407fea7c13355076f7f85e9a7bc0e293e3db96c1317a6e7d",
		},
		{
			// Same ground-truth process, with two flattened calls (a Squads
			// call followed by a System Program transfer -- simulated_instructions
			// is a flat list with no nesting/index, so this is simply two
			// entries rather than one call with an attached inner call).
			name: "solana simulate transaction result with two flattened calls",
			meta: &RequestChainMetadata{
				Solana: &SolanaChainMetadata{
					SimulateTransactionResult: &SimulateTransactionResult{
						Instructions: []SimulatedInstruction{
							{
								ProgramKey:         "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf",
								InstructionDataHex: "1f9a5c",
							},
							{
								ProgramKey:         "11111111111111111111111111111111",
								InstructionDataHex: "0200000001000000000000000000",
							},
						},
					},
				},
			},
			rustBytes:  "010100000000000001020000002b000000535144533465703635543836397a4d4d424b7975557136614436456754753870734d6a6b766a3532704366060000003166396135632000000031313131313131313131313131313131313131313131313131313131313131311c00000030323030303030303031303030303030303030303030303030303030",
			rustDigest: "4aeea9c96616756d881a8122fcb4f1ddd96183cc27056be4900c2061019453a6",
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
