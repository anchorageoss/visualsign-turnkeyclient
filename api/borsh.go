package api

import (
	"fmt"
	"sort"

	borsh "github.com/near/borsh-go"

	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
)

// Borsh mirror types matching the Rust generated/parser.rs field declaration order.
// The parser computes metadata_digest = sha256(borsh::to_vec(&chain_metadata)).

// ethereumVariant is the Borsh discriminant for chain_metadata::Metadata::Ethereum.
// Matches the Rust enum's default discriminant (use_discriminant=true, first variant = 0).
const ethereumVariant = borsh.Enum(0)

// borshChainMetadata mirrors parser.rs ChainMetadata.
type borshChainMetadata struct {
	Metadata *borshMetadataEnum // Option<chain_metadata::Metadata>
}

// borshMetadataEnum mirrors chain_metadata::Metadata (enum, use_discriminant=true).
// Ethereum discriminant = 0, Solana discriminant = 1.
type borshMetadataEnum struct {
	Enum     borsh.Enum            `borsh_enum:"true"`
	Ethereum borshEthereumMetadata // variant 0
	Solana   borshSolanaMetadata   // variant 1 — placeholder, never active in Ethereum path
}

// borshEthereumMetadata mirrors parser.rs EthereumMetadata.
// Field order must match the Rust struct declaration.
//
// ABIMappings is wire-compatible with Rust's HashMap<String, Abi>: Borsh encodes
// both as `u32 length || sorted [key, value] pairs`. We materialize the sort
// explicitly here rather than rely on borsh-go's internal map handling.
type borshEthereumMetadata struct {
	NetworkID   *string         // Option<String>
	ABIMappings []borshAbiEntry // serialized as HashMap<String, Abi> — sorted by Address
}

// borshAbiEntry is one (address, ABI) pair in ABIMappings. The field order
// (Address then Abi) must match Rust's tuple/HashMap entry layout.
type borshAbiEntry struct {
	Address string
	Abi     borshAbi
}

// borshAbi mirrors parser.rs Abi.
type borshAbi struct {
	Value     string
	Signature *borshSignatureMetadata // Option<SignatureMetadata>
}

// borshSignatureMetadata mirrors parser.rs SignatureMetadata.
type borshSignatureMetadata struct {
	Value    string
	Metadata []borshKeyValue // Vec<Metadata>
}

// borshKeyValue mirrors parser.rs Metadata (key-value pair).
type borshKeyValue struct {
	Key   string
	Value string
}

// borshSolanaMetadata is a placeholder for variant 1 of borshMetadataEnum.
// It is never serialized when the Ethereum variant (0) is active.
type borshSolanaMetadata struct{}

func toBorshSignature(s *ABISignature) *borshSignatureMetadata {
	if s == nil {
		return nil
	}
	kvs := make([]borshKeyValue, len(s.Metadata))
	for i, kv := range s.Metadata {
		kvs[i] = borshKeyValue(kv)
	}
	return &borshSignatureMetadata{Value: s.Value, Metadata: kvs}
}

// BorshBytes returns borsh::to_vec(&chain_metadata) — the canonical bytes the
// visualsign-parser hashes for metadata_digest. SHA256 of these bytes equals
// MetadataDigestHex(). Anchorage's HSM uses these same bytes to self-verify the
// digest off-chain (see PRS-192). Returns the Borsh encoding of
// ChainMetadata{metadata:None} ([]byte{0x00}) when r is nil or r.Ethereum is nil.
func (r *RequestChainMetadata) BorshBytes() ([]byte, error) {
	cm := r.toBorshChainMetadata()
	b, err := borsh.Serialize(cm)
	if err != nil {
		return nil, fmt.Errorf("borsh-serialize chain_metadata: %w", err)
	}
	return b, nil
}

// MetadataDigestHex returns the hex-encoded SHA-256 of the Borsh encoding of r,
// matching the metadata_digest the visualsign-parser computes for the same input.
func (r *RequestChainMetadata) MetadataDigestHex() (string, error) {
	b, err := r.BorshBytes()
	if err != nil {
		return "", err
	}
	return manifest.ComputeHash(b), nil
}

func (r *RequestChainMetadata) toBorshChainMetadata() borshChainMetadata {
	if r == nil || r.Ethereum == nil {
		return borshChainMetadata{Metadata: nil}
	}
	eth := r.Ethereum
	entries := make([]borshAbiEntry, 0, len(eth.ABIMappings))
	for addr, abi := range eth.ABIMappings {
		entries = append(entries, borshAbiEntry{
			Address: addr,
			Abi: borshAbi{
				Value:     abi.Value,
				Signature: toBorshSignature(abi.Signature),
			},
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Address < entries[j].Address
	})
	return borshChainMetadata{
		Metadata: &borshMetadataEnum{
			Enum: ethereumVariant,
			Ethereum: borshEthereumMetadata{
				NetworkID:   eth.NetworkID,
				ABIMappings: entries,
			},
		},
	}
}
