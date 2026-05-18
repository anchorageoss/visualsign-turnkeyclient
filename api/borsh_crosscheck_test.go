package api

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	borsh "github.com/near/borsh-go"
)

// TestCrosscheckGoVsRustOnDeployedProto pins Go's Borsh against Rust borsh::to_vec
// output for the exact same ChainMetadata struct, using the parser proto at
// visualsign-parser@2276b71b (the version Pepe identified as deployed).
// Ground truth from `cargo run --example dump_borsh` in that worktree.
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
			rustBytes:  "01000110000000455448455245554d5f4d41494e4e4554010000002a000000307861306238363939316336323138623336633164313964346132653965623063653336303665623438150000005b7b226e616d65223a227472616e73666572227d5d00",
			rustDigest: "759f221869fe6a6d8da7ad5981a109ec3b87611465fe19da4c2d37170eabebd6",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cm := tc.meta.toBorshChainMetadata()
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
