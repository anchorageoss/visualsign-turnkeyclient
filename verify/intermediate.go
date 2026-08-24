package verify

import (
	"encoding/json"
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
// Bumped to 2 for SolanaSimulatedInstruction.RpcParsedData.
const SolanaIntermediateSchemaVersion uint16 = 2

// RegisteredSource mirrors intermediate.rs RegisteredSource: where a program
// ID was registered
type RegisteredSource borsh.Enum

const (
	RegisteredSourceNative RegisteredSource = iota
	RegisteredSourcePreset
	RegisteredSourceThirdParty
	RegisteredSourceCallerSupplied
	RegisteredSourceUnregistered
)

func (s RegisteredSource) String() string {
	switch s {
	case RegisteredSourceNative:
		return "Native"
	case RegisteredSourcePreset:
		return "Preset"
	case RegisteredSourceThirdParty:
		return "ThirdParty"
	case RegisteredSourceCallerSupplied:
		return "CallerSupplied"
	case RegisteredSourceUnregistered:
		return "Unregistered"
	default:
		return fmt.Sprintf("RegisteredSource(%d)", uint8(s))
	}
}

func (s RegisteredSource) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

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
	// SimulatedInstructions is a flat list of every call (top-level and
	// inner/CPI alike) a caller-supplied transaction simulation observed.
	// Independent of Instructions (static decode): no positional correlation,
	// no index, no nesting.
	SimulatedInstructions []SolanaSimulatedInstruction `json:"simulatedInstructions,omitempty"`
}

// SolanaIntermediateInstruction mirrors intermediate.rs SolanaIntermediateInstruction.
// Field order matches the Rust struct exactly (Borsh is positional):
// IdlParseError and RegisteredSource are appended after ParsedInstructionData
// because they postdate the schema shipped on main -- a consumer built
// against the prior shape simply stops reading before them.
type SolanaIntermediateInstruction struct {
	ProgramKey            string                           `json:"programKey"`
	Accounts              []SolanaAccount                  `json:"accounts"`
	InstructionDataHex    string                           `json:"instructionDataHex"`
	AddressTableLookups   []SolanaSingleAddressTableLookup `json:"addressTableLookups"`
	ParsedInstructionData *SolanaParsedInstructionDataIo   `json:"parsedInstructionData,omitempty"`
	IdlParseError         *SolanaIdlParseError             `json:"idlParseError,omitempty"`
	RegisteredSource      RegisteredSource                 `json:"registeredSource"`
}

// SolanaSimulatedInstruction mirrors intermediate.rs SolanaSimulatedInstruction:
type SolanaSimulatedInstruction struct {
	Index                 uint32                            `json:"index"`
	StackHeight           uint32                            `json:"stackHeight"`
	ProgramKey            string                            `json:"programKey"`
	Accounts              []SolanaAccount                   `json:"accounts"`
	InstructionDataHex    string                            `json:"instructionDataHex"`
	RegisteredSource      RegisteredSource                  `json:"registeredSource"`
	ParsedInstructionData *SolanaParsedInstructionDataIo    `json:"parsedInstructionData,omitempty"`
	RpcParsedData         *SolanaRpcParsedInstructionDataIo `json:"rpcParsedData,omitempty"`
	IdlParseError         *SolanaIdlParseError              `json:"idlParseError,omitempty"`
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

// SolanaRpcParsedInstructionDataIo mirrors intermediate.rs
// SolanaRpcParsedInstructionDataIo: the RPC's own jsonParsed decode of a
// simulated instruction, distinct from the parser's own IDL-decoded
// SolanaParsedInstructionDataIo.
type SolanaRpcParsedInstructionDataIo struct {
	InstructionType string `json:"instructionType"`
	InfoJSON        string `json:"infoJson"`
}

// SolanaIdlDataOrAccountsError mirrors the payload shape shared by
// intermediate.rs SolanaIdlParseError's DataParseError and AccountsMapError
// struct variants.
type SolanaIdlDataOrAccountsError struct {
	InstructionName string `json:"instructionName"`
	Error           string `json:"error"`
}

// SolanaIdlParseError mirrors intermediate.rs SolanaIdlParseError: why IDL
// decode failed for an instruction, when it was attempted at all. Complex
// Borsh enum -- exactly one of the fields below is populated, selected by
// Enum. Field order after Enum must match the Rust variant declaration
// order exactly (DataParseError, AccountsMapError, DiscriminatorNotFound,
// IdlResolutionError).
type SolanaIdlParseError struct {
	Enum                  borsh.Enum `borsh_enum:"true"`
	DataParseError        SolanaIdlDataOrAccountsError
	AccountsMapError      SolanaIdlDataOrAccountsError
	DiscriminatorNotFound string
	IdlResolutionError    string
}

func (e *SolanaIdlParseError) MarshalJSON() ([]byte, error) {
	switch e.Enum {
	case 0:
		return json.Marshal(map[string]any{"type": "DataParseError", "instructionName": e.DataParseError.InstructionName, "error": e.DataParseError.Error})
	case 1:
		return json.Marshal(map[string]any{"type": "AccountsMapError", "instructionName": e.AccountsMapError.InstructionName, "error": e.AccountsMapError.Error})
	case 2:
		return json.Marshal(map[string]any{"type": "DiscriminatorNotFound", "error": e.DiscriminatorNotFound})
	case 3:
		return json.Marshal(map[string]any{"type": "IdlResolutionError", "error": e.IdlResolutionError})
	default:
		return json.Marshal(map[string]any{"type": fmt.Sprintf("SolanaIdlParseError(%d)", uint8(e.Enum))})
	}
}

// isZero reports whether this is the zero value borsh-go produces for an
// Option::None: Enum 0 (DataParseError) with an empty payload. The parser
// never emits a genuine DataParseError with both strings empty (error is
// always a real, non-empty message from solana_parser), so this degenerate
// shape unambiguously means None in practice, same tradeoff as the other
// isZero methods below.
func (e *SolanaIdlParseError) isZero() bool {
	return e.Enum == 0 && e.DataParseError.InstructionName == "" && e.DataParseError.Error == ""
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
		e := out.Instructions[i].IdlParseError
		if e != nil && e.isZero() {
			out.Instructions[i].IdlParseError = nil
		}
	}
	for i := range out.SimulatedInstructions {
		p := out.SimulatedInstructions[i].ParsedInstructionData
		if p != nil && p.isZero() {
			out.SimulatedInstructions[i].ParsedInstructionData = nil
		}
		r := out.SimulatedInstructions[i].RpcParsedData
		if r != nil && r.isZero() {
			out.SimulatedInstructions[i].RpcParsedData = nil
		}
		e := out.SimulatedInstructions[i].IdlParseError
		if e != nil && e.isZero() {
			out.SimulatedInstructions[i].IdlParseError = nil
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

// isZero reports whether every field of the RPC-parsed instruction data is the
// zero value — the shape borsh-go produces for an Option::None.
func (r *SolanaRpcParsedInstructionDataIo) isZero() bool {
	return r.InstructionType == "" && r.InfoJSON == ""
}

func nilIfEmpty(s *string) *string {
	if s != nil && *s == "" {
		return nil
	}
	return s
}
