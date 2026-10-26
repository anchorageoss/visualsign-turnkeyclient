package verify

import (
	"encoding/binary"
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

// SolanaIntermediateMinSchemaVersion and SolanaIntermediateMaxSchemaVersion
// bound the schema_version values DecodeSolanaIntermediateOutput accepts. Max
// matches SOLANA_INTERMEDIATE_SCHEMA_VERSION in the parser's intermediate.rs.
//
// Every version in the range is decoded with its own layout, so a client
// built from this package works against parsers on either side of a schema
// rollout. Versions outside the range are refused rather than guessed at.
//
//   - 4: the layout mirrored since parser PR #546.
//   - 5: adds NativeInstructionDecoder immediately after schema_version
//     (parser PR #575) and the SolanaSimulationErrorSimulationUnsupported
//     variant. Every other field is unchanged from 4.
const (
	SolanaIntermediateMinSchemaVersion uint16 = 4
	SolanaIntermediateMaxSchemaVersion uint16 = 5
)

// SolanaIntermediateSchemaVersion is the newest schema_version this client
// understands.
//
// Deprecated: the decoder accepts a range of versions. Use
// SolanaIntermediateMinSchemaVersion and SolanaIntermediateMaxSchemaVersion,
// and read SolanaIntermediateOutput.SchemaVersion for the version a given
// output carries.
const SolanaIntermediateSchemaVersion = SolanaIntermediateMaxSchemaVersion

// solanaNativeInstructionDecoderSince is the first schema_version that carries
// the native_instruction_decoder byte after schema_version.
const solanaNativeInstructionDecoderSince uint16 = 5

// AddressTableLookupPlaceholder is the value the parser emits in place of a
// pubkey for an account an instruction reads through an address lookup table
// (intermediate.rs ADDRESS_TABLE_LOOKUP). It appears in
// SolanaParsedInstructionDataIo.NamedAccounts and ProgramCallArgsJSON on the
// IDL and native paths alike, and in SolanaJSONParsedInstructionDataIo.ParsedJSON.
const AddressTableLookupPlaceholder = "ADDRESS_TABLE_LOOKUP"

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

// SolanaNativeInstructionDecoder mirrors intermediate.rs
// SolanaNativeInstructionDecoder: which native decoder the parser build that
// produced the output had. It is a build capability, not a per-instruction
// result, and lets a consumer tell a disabled decoder from a real decode
// failure reported in SolanaJSONParseError. Added in schema_version 5.
type SolanaNativeInstructionDecoder borsh.Enum

const (
	// SolanaNativeInstructionDecoderComputeBudgetOnly: the parser was built
	// without its json-parsed feature; only Compute Budget has a native
	// decoder.
	SolanaNativeInstructionDecoderComputeBudgetOnly SolanaNativeInstructionDecoder = iota
	// SolanaNativeInstructionDecoderJSONParsed: Solana's jsonParsed decoder
	// plus the parser's own Compute Budget decoder.
	SolanaNativeInstructionDecoderJSONParsed
)

func (d SolanaNativeInstructionDecoder) String() string {
	switch d {
	case SolanaNativeInstructionDecoderComputeBudgetOnly:
		return "ComputeBudgetOnly"
	case SolanaNativeInstructionDecoderJSONParsed:
		return "JsonParsed"
	default:
		return fmt.Sprintf("SolanaNativeInstructionDecoder(%d)", uint8(d))
	}
}

func (d SolanaNativeInstructionDecoder) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// SolanaSimulationError mirrors intermediate.rs SolanaSimulationError: why a
// caller-supplied simulateTransaction result could not be read. Unit variants;
// the detail is logged parser-side rather than encoded.
type SolanaSimulationError borsh.Enum

const (
	// Discriminants start at 1, matching the Rust enum's explicit values
	// (#[borsh(use_discriminant = true)]). 0 is not a variant, so the zero value
	// borsh-go produces for Option::None cannot be mistaken for a real error.
	SolanaSimulationErrorInvalidBase64 SolanaSimulationError = iota + 1
	SolanaSimulationErrorInvalidJSON
	SolanaSimulationErrorSimulationFailed
	SolanaSimulationErrorCallerIdlRecordsUnusable
	SolanaSimulationErrorCompiledInstruction
	SolanaSimulationErrorInvalidInstructionData
	// SolanaSimulationErrorSimulationUnsupported: the parser was built
	// without its simulation feature, so a supplied simulation was not read.
	// Added alongside schema_version 5.
	SolanaSimulationErrorSimulationUnsupported
)

func (e SolanaSimulationError) String() string {
	switch e {
	case SolanaSimulationErrorInvalidBase64:
		return "InvalidBase64"
	case SolanaSimulationErrorInvalidJSON:
		return "InvalidJson"
	case SolanaSimulationErrorSimulationFailed:
		return "SimulationFailed"
	case SolanaSimulationErrorCallerIdlRecordsUnusable:
		return "CallerIdlRecordsUnusable"
	case SolanaSimulationErrorCompiledInstruction:
		return "CompiledInstruction"
	case SolanaSimulationErrorInvalidInstructionData:
		return "InvalidInstructionData"
	case SolanaSimulationErrorSimulationUnsupported:
		return "SimulationUnsupported"
	default:
		return fmt.Sprintf("SolanaSimulationError(%d)", uint8(e))
	}
}

func (e SolanaSimulationError) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

// SolanaIntermediateOutput mirrors intermediate.rs SolanaIntermediateOutput.
// schema_version is the first field so decoders can gate on it before trusting
// the remaining layout.
//
// Build values of this type with DecodeSolanaIntermediateOutput, not
// borsh.Deserialize: NativeInstructionDecoder is present on the wire only from
// schema_version 5, so it is excluded from the struct's Borsh layout
// (borsh_skip) and handled by the decoder. borsh.Serialize of this struct
// likewise produces the schema_version 4 field layout.
type SolanaIntermediateOutput struct {
	SchemaVersion uint16 `json:"schemaVersion"`
	// NativeInstructionDecoder is the parser build's native decoder
	// capability. Nil for schema_version 4, which does not carry it.
	NativeInstructionDecoder *SolanaNativeInstructionDecoder `json:"nativeInstructionDecoder,omitempty" borsh_skip:"true"`
	AccountKeys              []string                        `json:"accountKeys"`
	ProgramKeys              []string                        `json:"programKeys"`
	Instructions             []SolanaIntermediateInstruction `json:"instructions"`
	Transfers                []SolTransfer                   `json:"transfers"`
	SplTransfers             []SplTransfer                   `json:"splTransfers"`
	RecentBlockhash          string                          `json:"recentBlockhash"`
	AddressTableLookups      []SolanaAddressTableLookup      `json:"addressTableLookups"`
	// SimulatedInstructions is a flat list of every call (top-level and
	// inner/CPI alike) a caller-supplied transaction simulation observed.
	// Independent of Instructions (static decode): no positional correlation,
	// no index, no nesting.
	SimulatedInstructions []SolanaSimulatedInstruction `json:"simulatedInstructions,omitempty"`
	// SimulationError says why a supplied simulation could not be read. Nil
	// means it was read or none was sent, so SimulatedInstructions is
	// authoritative: empty there means the simulation had no inner
	// instructions, not that we failed to read it.
	SimulationError *SolanaSimulationError `json:"simulationError,omitempty"`
}

// SolanaIntermediateInstruction mirrors intermediate.rs SolanaIntermediateInstruction.
// Field order matches the Rust struct exactly (Borsh is positional and has no
// field-skipping). The schema_version is what carries compatibility here:
// any field change must bump it.
type SolanaIntermediateInstruction struct {
	ProgramKey          string                           `json:"programKey"`
	Accounts            []SolanaAccount                  `json:"accounts"`
	InstructionDataHex  string                           `json:"instructionDataHex"`
	AddressTableLookups []SolanaSingleAddressTableLookup `json:"addressTableLookups"`
	// ParsedInstructionData is the IDL decode, or for a Native program the
	// parser's native decode (empty IdlSource and IdlHash; since
	// schema_version 4). Nil when neither applies; IdlParseError and
	// SolanaJSONParseError say why.
	//
	// An account the instruction reads through an address lookup table is
	// not a pubkey: it is the literal placeholder AddressTableLookupPlaceholder
	// in NamedAccounts, in ProgramCallArgsJSON, and in
	// SolanaJSONParsedData.ParsedJSON. Check for it before treating a value
	// as an address.
	ParsedInstructionData *SolanaParsedInstructionDataIo `json:"parsedInstructionData,omitempty"`
	IdlParseError         *SolanaIdlParseError           `json:"idlParseError,omitempty"`
	RegisteredSource      RegisteredSource               `json:"registeredSource"`
	// SolanaJSONParsedData is Solana's own jsonParsed decode
	// (solana_transaction_status) of a Native program instruction, run by the
	// parser, or the parser's own decode for Compute Budget. Nil for other
	// programs or on error. Added in schema_version 3.
	SolanaJSONParsedData *SolanaJSONParsedInstructionDataIo `json:"solanaJsonParsedData,omitempty"`
	// SolanaJSONParseError says why a Native program instruction has no
	// ParsedInstructionData: the program has no native decoder (e.g. SPL Stake
	// Pool), the decoder rejected the instruction, or its decode could not be
	// mapped. Nil otherwise, including when an IDL decode already explains
	// the instruction. Added in schema_version 3.
	SolanaJSONParseError *string `json:"solanaJsonParseError,omitempty"`
}

// SolanaSimulatedInstruction mirrors intermediate.rs SolanaSimulatedInstruction.
type SolanaSimulatedInstruction struct {
	Index              uint32           `json:"index"`
	StackHeight        uint32           `json:"stackHeight"`
	ProgramKey         string           `json:"programKey"`
	Accounts           []string         `json:"accounts"`
	InstructionDataHex string           `json:"instructionDataHex"`
	RegisteredSource   RegisteredSource `json:"registeredSource"`
	// ParsedInstructionData is the IDL decode, or for a Native program the
	// same native decode a top-level instruction gets (since schema_version
	// 4). Nil when neither applies.
	ParsedInstructionData *SolanaParsedInstructionDataIo `json:"parsedInstructionData,omitempty"`
	// SolanaRpcParsedData is the RPC's own jsonParsed decode, for the programs
	// it returns that way. Nil for partially-decoded instructions.
	SolanaRpcParsedData *SolanaRpcParsedInstructionDataIo `json:"solanaRpcParsedData,omitempty"`
	IdlParseError       *SolanaIdlParseError              `json:"idlParseError,omitempty"`
	// SolanaJSONParseError says why a Native program instruction has no
	// ParsedInstructionData, as on SolanaIntermediateInstruction. Nil
	// otherwise. Added in schema_version 4.
	SolanaJSONParseError *string `json:"solanaJsonParseError,omitempty"`
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
// (iteration order is irrelevant on decode). IdlSource and IdlHash are empty
// for a native decode (a Native program instruction, schema_version 4+).
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
	Program    string `json:"program"`
	ParsedJSON string `json:"parsedJson"`
}

// SolanaJSONParsedInstructionDataIo mirrors intermediate.rs
// SolanaJsonParsedInstructionDataIo: a top-level instruction decoded by
// Solana's own jsonParsed decoder, run by the parser.
type SolanaJSONParsedInstructionDataIo struct {
	// Program is the decoder's program name, e.g. "system", "spl-token".
	Program string `json:"program"`
	// ParsedJSON is canonical JSON: {"info":..,"type":..} for a typed
	// instruction, a bare JSON string for SPL Memo.
	ParsedJSON string `json:"parsedJson"`
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
// Solana intermediate output. It accepts schema_version
// SolanaIntermediateMinSchemaVersion through SolanaIntermediateMaxSchemaVersion,
// decoding each with its own layout, and rejects any other version, so a
// parser-side layout change surfaces as an explicit error rather than a
// silently misdecoded struct.
func DecodeSolanaIntermediateOutput(b []byte) (*SolanaIntermediateOutput, error) {
	// Gate on schema_version (the leading u16, little-endian) before decoding
	// the rest: another version's layout would otherwise fail mid-decode with
	// a byte-level error, or decode into the wrong fields, instead of this one.
	if len(b) < 2 {
		return nil, fmt.Errorf("solana intermediate output too short for schema_version: %d bytes", len(b))
	}
	v := binary.LittleEndian.Uint16(b)
	if v < SolanaIntermediateMinSchemaVersion || v > SolanaIntermediateMaxSchemaVersion {
		return nil, fmt.Errorf(
			"unsupported solana intermediate output schema_version %d (this client supports %d through %d)",
			v, SolanaIntermediateMinSchemaVersion, SolanaIntermediateMaxSchemaVersion)
	}

	body := b
	var nativeDecoder *SolanaNativeInstructionDecoder
	if v >= solanaNativeInstructionDecoderSince {
		// Schema 5 inserts a one-byte native_instruction_decoder tag after
		// schema_version and leaves every later field as in schema 4. Read
		// and validate the tag, then drop it so the shared mirror struct
		// decodes the rest.
		if len(b) < 3 {
			return nil, fmt.Errorf(
				"solana intermediate output schema_version %d too short for native_instruction_decoder: %d bytes",
				v, len(b))
		}
		d := SolanaNativeInstructionDecoder(b[2])
		if d != SolanaNativeInstructionDecoderComputeBudgetOnly && d != SolanaNativeInstructionDecoderJSONParsed {
			return nil, fmt.Errorf("unknown solana intermediate output native_instruction_decoder tag %d", b[2])
		}
		nativeDecoder = &d
		body = make([]byte, 0, len(b)-1)
		body = append(body, b[:2]...)
		body = append(body, b[3:]...)
	}

	var out SolanaIntermediateOutput
	if err := borsh.Deserialize(&out, body); err != nil {
		return nil, fmt.Errorf("borsh-decode solana intermediate output: %w", err)
	}
	out.NativeInstructionDecoder = nativeDecoder
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
	// 0 is not a SolanaSimulationError variant, so it can only be a decoded None.
	if out.SimulationError != nil && *out.SimulationError == 0 {
		out.SimulationError = nil
	}
	for i := range out.Instructions {
		p := out.Instructions[i].ParsedInstructionData
		if p != nil && p.isZero() {
			out.Instructions[i].ParsedInstructionData = nil
		}
		e := out.Instructions[i].IdlParseError
		if e != nil && e.isZero() {
			out.Instructions[i].IdlParseError = nil
		}
		j := out.Instructions[i].SolanaJSONParsedData
		if j != nil && j.isZero() {
			out.Instructions[i].SolanaJSONParsedData = nil
		}
		out.Instructions[i].SolanaJSONParseError = nilIfEmpty(out.Instructions[i].SolanaJSONParseError)
	}
	for i := range out.SimulatedInstructions {
		p := out.SimulatedInstructions[i].ParsedInstructionData
		if p != nil && p.isZero() {
			out.SimulatedInstructions[i].ParsedInstructionData = nil
		}
		r := out.SimulatedInstructions[i].SolanaRpcParsedData
		if r != nil && r.isZero() {
			out.SimulatedInstructions[i].SolanaRpcParsedData = nil
		}
		e := out.SimulatedInstructions[i].IdlParseError
		if e != nil && e.isZero() {
			out.SimulatedInstructions[i].IdlParseError = nil
		}
		out.SimulatedInstructions[i].SolanaJSONParseError = nilIfEmpty(out.SimulatedInstructions[i].SolanaJSONParseError)
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
	return r.Program == "" && r.ParsedJSON == ""
}

// isZero reports whether every field of the jsonParsed instruction data is the
// zero value — the shape borsh-go produces for an Option::None.
func (j *SolanaJSONParsedInstructionDataIo) isZero() bool {
	return j.Program == "" && j.ParsedJSON == ""
}

func nilIfEmpty(s *string) *string {
	if s != nil && *s == "" {
		return nil
	}
	return s
}
