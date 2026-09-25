package api

import (
	"encoding/base64"
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

// solanaVariant is the Borsh discriminant for chain_metadata::Metadata::Solana.
// Matches the Rust enum's default discriminant (use_discriminant=true, second variant = 1).
const solanaVariant = borsh.Enum(1)

// nearVariant is the Borsh discriminant for chain_metadata::Metadata::Near.
// Matches the Rust enum's default discriminant (use_discriminant=true, third variant = 2).
const nearVariant = borsh.Enum(2)

// borshChainMetadata mirrors parser.rs ChainMetadata.
type borshChainMetadata struct {
	Metadata *borshMetadataEnum // Option<chain_metadata::Metadata>
}

// borshMetadataEnum mirrors chain_metadata::Metadata (enum, use_discriminant=true).
// Ethereum discriminant = 0, Solana discriminant = 1.
type borshMetadataEnum struct {
	Enum     borsh.Enum            `borsh_enum:"true"`
	Ethereum borshEthereumMetadata // variant 0
	Solana   borshSolanaMetadata   // variant 1
	Near     borshNearMetadata     // variant 2
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

// borshAbi mirrors parser.rs Abi. Field order matches the proto tag order
// (value, signature, abi_type, implementation_address), which is the Rust struct
// declaration order Borsh serializes in.
type borshAbi struct {
	Value                 string
	Signature             *borshSignatureMetadata // Option<SignatureMetadata>
	AbiType               *int32                  // Option<i32> — proto enum number (prost enumeration)
	ImplementationAddress *string                 // Option<String>
}

// abiTypeBorshNumber maps the wire string form of AbiType to the proto enum
// number Borsh hashes. The parser sends the string over JSON but stores the
// enum as i32, so the digest is computed over these numbers.
var abiTypeBorshNumber = map[AbiType]int32{
	AbiTypeUnspecified:    0,
	AbiTypeImplementation: 1,
	AbiTypeProxy:          2,
}

// toBorshAbiType converts an optional AbiType to its Borsh Option<i32> form.
// nil maps to None (nil *int32). An unrecognized value is an error: a wrong
// digest is worse than a failed call.
func toBorshAbiType(t *AbiType) (*int32, error) {
	if t == nil {
		return nil, nil
	}
	n, ok := abiTypeBorshNumber[*t]
	if !ok {
		return nil, fmt.Errorf("unknown abi_type %q", *t)
	}
	return &n, nil
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

// borshSolanaMetadata mirrors parser.rs SolanaMetadata in Rust declaration order.
type borshSolanaMetadata struct {
	NetworkID                  *string                // Option<String>
	Idl                        *borshIdl              // Option<Idl>
	IdlMappings                []borshIdlMappingEntry // BTreeMap<String, Idl> — must be sorted by ProgramID
	SimulatedTransactionResult *string                // Option<String> — base64 raw simulateTransaction RPC response
}

// borshIdl mirrors parser.rs Idl in Rust declaration order.
type borshIdl struct {
	Value       string
	IdlType     *int32                  // Option<i32> — proto enum number (prost enumeration)
	IdlVersion  *string                 // Option<String>
	Signature   *borshSignatureMetadata // Option<SignatureMetadata>
	ProgramName *string                 // Option<String>
}

// borshIdlMappingEntry is one (program_id, Idl) pair in IdlMappings, sorted by ProgramID.
type borshIdlMappingEntry struct {
	ProgramID string
	Idl       borshIdl
}

// borshNearMetadata mirrors parser.rs NearMetadata in Rust declaration order.
//
// TokenMappings is Rust's BTreeMap<String, TokenMetadataEntry>, which Borsh
// encodes as `u32 length || pairs in ascending key order`. Go map iteration is
// randomized, so the sort is materialized explicitly here: an unsorted encoding
// would produce a different digest for the same input on different runs.
type borshNearMetadata struct {
	NetworkID     *string                  // Option<String>
	TokenMappings []borshTokenMappingEntry // BTreeMap<String, TokenMetadataEntry> — sorted by AssetID
}

// borshTokenMappingEntry is one (asset_id, TokenMetadataEntry) pair in
// TokenMappings. The field order (AssetID then Entry) must match Rust's map
// entry layout.
type borshTokenMappingEntry struct {
	AssetID string
	Entry   borshTokenMetadataEntry
}

// borshTokenMetadataEntry mirrors parser.rs TokenMetadataEntry. Field order
// matches the proto tag order (value, signature, origin_chain), which is the
// Rust struct declaration order Borsh serializes in.
type borshTokenMetadataEntry struct {
	Value       string                  // String
	Signature   *borshSignatureMetadata // Option<SignatureMetadata>
	OriginChain *int32                  // Option<i32> — proto enum number (prost enumeration)
}

// tokenOriginChainBorshNumber maps the wire string form of TokenOriginChain to
// the proto enum number Borsh hashes. The parser sends the string over JSON but
// stores the enum as i32, so the digest is computed over these numbers — the
// same split abiTypeBorshNumber handles for AbiType.
var tokenOriginChainBorshNumber = map[TokenOriginChain]int32{
	TokenOriginChainUnspecified: 0,
	TokenOriginChainNear:        1,
	TokenOriginChainEthereum:    2,
	TokenOriginChainSolana:      3,
}

// toBorshTokenOriginChain converts an optional TokenOriginChain to its Borsh
// Option<i32> form. nil maps to None. An unrecognized value is an error: a
// wrong digest is worse than a failed call.
func toBorshTokenOriginChain(c *TokenOriginChain) (*int32, error) {
	if c == nil {
		return nil, nil
	}
	n, ok := tokenOriginChainBorshNumber[*c]
	if !ok {
		return nil, fmt.Errorf("unknown origin_chain %q", *c)
	}
	return &n, nil
}

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
// visualsign-parser hashes for metadata_digest. hex.EncodeToString of
// SHA256 over these bytes equals MetadataDigestHex(). These bytes let a
// verifier recompute the digest off-chain. Returns the Borsh encoding of
// ChainMetadata{metadata: None} ([]byte{0x00}) when r is nil, or when no
// variant is set.
func (r *RequestChainMetadata) BorshBytes() ([]byte, error) {
	cm, err := r.toBorshChainMetadata()
	if err != nil {
		return nil, err
	}
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

func (r *RequestChainMetadata) toBorshChainMetadata() (borshChainMetadata, error) {
	if r == nil {
		return borshChainMetadata{Metadata: nil}, nil
	}
	if set := r.setVariants(); len(set) > 1 {
		return borshChainMetadata{}, fmt.Errorf(
			"RequestChainMetadata: exactly one variant must be set, got %d %v", len(set), set)
	}
	switch {
	case r.Ethereum != nil:
		return r.toBorshChainMetadataEthereum()
	case r.Solana != nil:
		return r.toBorshChainMetadataSolana()
	case r.Near != nil:
		return r.toBorshChainMetadataNear()
	default:
		return borshChainMetadata{Metadata: nil}, nil
	}
}

func (r *RequestChainMetadata) toBorshChainMetadataEthereum() (borshChainMetadata, error) {
	eth := r.Ethereum
	entries := make([]borshAbiEntry, 0, len(eth.ABIMappings))
	for addr, abi := range eth.ABIMappings {
		abiType, err := toBorshAbiType(abi.AbiType)
		if err != nil {
			return borshChainMetadata{}, fmt.Errorf("abi_mappings[%q]: %w", addr, err)
		}
		entries = append(entries, borshAbiEntry{
			Address: addr,
			Abi: borshAbi{
				Value:                 abi.Value,
				Signature:             toBorshSignature(abi.Signature),
				AbiType:               abiType,
				ImplementationAddress: abi.ImplementationAddress,
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
	}, nil
}

func (r *RequestChainMetadata) toBorshChainMetadataSolana() (borshChainMetadata, error) {
	sol := r.Solana
	var rawJSON *string
	if len(sol.SimulatedTransactionResult) > 0 {
		encoded := base64.StdEncoding.EncodeToString(sol.SimulatedTransactionResult)
		rawJSON = &encoded
	}
	return borshChainMetadata{
		Metadata: &borshMetadataEnum{
			Enum: solanaVariant,
			Solana: borshSolanaMetadata{
				// TODO: pass real entries once SolanaChainMetadata exposes IdlMappings.
				IdlMappings:                sortIdlMappings(nil),
				SimulatedTransactionResult: rawJSON,
			},
		},
	}, nil
}

func (r *RequestChainMetadata) toBorshChainMetadataNear() (borshChainMetadata, error) {
	near := r.Near
	entries := make([]borshTokenMappingEntry, 0, len(near.TokenMappings))
	for assetID, token := range near.TokenMappings {
		originChain, err := toBorshTokenOriginChain(token.OriginChain)
		if err != nil {
			return borshChainMetadata{}, fmt.Errorf("token_mappings[%q]: %w", assetID, err)
		}
		entries = append(entries, borshTokenMappingEntry{
			AssetID: assetID,
			Entry: borshTokenMetadataEntry{
				Value:       token.Value,
				Signature:   toBorshSignature(token.Signature),
				OriginChain: originChain,
			},
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].AssetID < entries[j].AssetID
	})
	return borshChainMetadata{
		Metadata: &borshMetadataEnum{
			Enum: nearVariant,
			Near: borshNearMetadata{
				NetworkID:     near.NetworkID,
				TokenMappings: entries,
			},
		},
	}, nil
}

// sortIdlMappings sorts idl_mappings by ProgramID, as Rust's BTreeMap encoding requires.
func sortIdlMappings(entries []borshIdlMappingEntry) []borshIdlMappingEntry {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ProgramID < entries[j].ProgramID
	})
	return entries
}
