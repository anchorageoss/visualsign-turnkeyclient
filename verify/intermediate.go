package verify

import (
	"fmt"

	"github.com/near/borsh-go"
)

// Borsh mirror of the Solana "intermediate output" — the machine-readable,
// chain-specific structured decode the visualsign-parser emits alongside the
// human-readable SignablePayload. The upstream source of truth is
// visualsign-parser's src/chain_parsers/visualsign-solana/src/intermediate.rs.
//
// Borsh is not self-describing: these structs must mirror the Rust types
// field-for-field in declaration order. Types map as: Rust String -> string,
// Vec<T> -> []T, Option<T> -> *T, u16 -> uint16, i32 -> int32,
// BTreeMap<String,String> -> map[string]string. JSON tags drive the verify
// command's structured output and do not affect Borsh (which is positional).

// SolanaIntermediateSchemaVersion is the schema_version this client understands.
// It matches SOLANA_INTERMEDIATE_SCHEMA_VERSION in the parser's intermediate.rs.
const SolanaIntermediateSchemaVersion uint16 = 1

// SolanaIntermediateOutput mirrors intermediate.rs SolanaIntermediateOutput.
// schema_version is the first field so decoders can gate on it before trusting
// the remaining layout.
type SolanaIntermediateOutput struct {
	SchemaVersion       uint16                          `json:"schemaVersion"`
	AccountKeys         []string                        `json:"accountKeys"`
	ProgramKeys         []string                        `json:"programKeys"`
	Instructions        []SolanaIntermediateInstruction `json:"instructions"`
	Transfers           []SolTransfer                   `json:"transfers"`
	SplTransfers        []SplTransfer                   `json:"splTransfers"`
	RecentBlockhash     string                          `json:"recentBlockhash"`
	AddressTableLookups []SolanaAddressTableLookup      `json:"addressTableLookups"`
}

// SolanaIntermediateInstruction mirrors intermediate.rs SolanaIntermediateInstruction.
type SolanaIntermediateInstruction struct {
	ProgramKey            string                           `json:"programKey"`
	Accounts              []SolanaAccount                  `json:"accounts"`
	InstructionDataHex    string                           `json:"instructionDataHex"`
	AddressTableLookups   []SolanaSingleAddressTableLookup `json:"addressTableLookups"`
	ParsedInstructionData *SolanaParsedInstructionDataIo   `json:"parsedInstructionData,omitempty"`
}

// SolanaAccount mirrors intermediate.rs SolanaAccount.
type SolanaAccount struct {
	AccountKey string `json:"accountKey"`
	Signer     bool   `json:"signer"`
	Writable   bool   `json:"writable"`
}

// SolTransfer mirrors intermediate.rs SolTransfer.
type SolTransfer struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Amount string `json:"amount"`
}

// SplTransfer mirrors intermediate.rs SplTransfer.
type SplTransfer struct {
	From      string   `json:"from"`
	To        string   `json:"to"`
	Amount    string   `json:"amount"`
	Owner     string   `json:"owner"`
	Signers   []string `json:"signers"`
	TokenMint *string  `json:"tokenMint,omitempty"`
	Decimals  *string  `json:"decimals,omitempty"`
	Fee       *string  `json:"fee,omitempty"`
}

// SolanaSingleAddressTableLookup mirrors intermediate.rs SolanaSingleAddressTableLookup.
type SolanaSingleAddressTableLookup struct {
	AddressTableKey string `json:"addressTableKey"`
	Index           int32  `json:"index"`
	Writable        bool   `json:"writable"`
}

// SolanaAddressTableLookup mirrors intermediate.rs SolanaAddressTableLookup.
type SolanaAddressTableLookup struct {
	AddressTableKey string  `json:"addressTableKey"`
	WritableIndexes []int32 `json:"writableIndexes"`
	ReadonlyIndexes []int32 `json:"readonlyIndexes"`
}

// SolanaParsedInstructionDataIo mirrors intermediate.rs SolanaParsedInstructionDataIo.
// NamedAccounts is a BTreeMap<String,String> on the Rust side; Borsh encodes it
// as a length-prefixed, key-sorted map, which decodes cleanly into a Go map
// (iteration order is irrelevant on decode).
type SolanaParsedInstructionDataIo struct {
	InstructionName     string            `json:"instructionName"`
	Discriminator       string            `json:"discriminator"`
	NamedAccounts       map[string]string `json:"namedAccounts"`
	ProgramCallArgsJSON string            `json:"programCallArgsJson"`
	IdlSource           string            `json:"idlSource"`
	IdlHash             string            `json:"idlHash"`
}

// DecodeSolanaIntermediateOutput decodes the raw Borsh bytes of the parser's
// Solana intermediate output. It rejects any schema_version other than the one
// this client mirrors, so a parser-side layout change surfaces as an explicit
// error rather than a silently misdecoded struct.
func DecodeSolanaIntermediateOutput(b []byte) (*SolanaIntermediateOutput, error) {
	var out SolanaIntermediateOutput
	if err := borsh.Deserialize(&out, b); err != nil {
		return nil, fmt.Errorf("borsh-decode solana intermediate output: %w", err)
	}
	if out.SchemaVersion != SolanaIntermediateSchemaVersion {
		return nil, fmt.Errorf(
			"unsupported solana intermediate output schema_version %d (this client supports %d)",
			out.SchemaVersion, SolanaIntermediateSchemaVersion)
	}
	normalizeOptionals(&out)
	return &out, nil
}

// normalizeOptionals restores Go nil for Borsh Option::None fields. borsh-go
// v0.3.1 decodes a None (tag byte 0) into a non-nil pointer to the zero value
// rather than a nil pointer, which would otherwise render None optionals as
// misleading empty objects/strings in the JSON output (and would not be elided
// by omitempty). We collapse a pointer whose pointee is the zero value back to
// nil. A genuine Some carrying an all-zero value is indistinguishable from None
// under borsh-go and is likewise treated as absent; the parser never emits such
// degenerate Some values for these fields (an IDL-matched instruction always
// has a name; token_mint/decimals/fee are only Some when they carry real data).
func normalizeOptionals(out *SolanaIntermediateOutput) {
	for i := range out.Instructions {
		p := out.Instructions[i].ParsedInstructionData
		if p != nil && p.isZero() {
			out.Instructions[i].ParsedInstructionData = nil
		}
	}
	for i := range out.SplTransfers {
		t := &out.SplTransfers[i]
		t.TokenMint = nilIfEmpty(t.TokenMint)
		t.Decimals = nilIfEmpty(t.Decimals)
		t.Fee = nilIfEmpty(t.Fee)
	}
}

// isZero reports whether every field of the parsed instruction data is the zero
// value — the shape borsh-go produces for an Option::None.
func (p *SolanaParsedInstructionDataIo) isZero() bool {
	return p.InstructionName == "" && p.Discriminator == "" && len(p.NamedAccounts) == 0 &&
		p.ProgramCallArgsJSON == "" && p.IdlSource == "" && p.IdlHash == ""
}

func nilIfEmpty(s *string) *string {
	if s != nil && *s == "" {
		return nil
	}
	return s
}
