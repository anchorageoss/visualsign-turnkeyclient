package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	borsh "github.com/near/borsh-go"
	"github.com/stretchr/testify/require"

	"github.com/anchorageoss/visualsign-turnkeyclient/testdata"
)

// solanaIntermediateSample is the captured local-parser fixture (see
// testdata/solana_intermediate_sample.json).
type solanaIntermediateSample struct {
	UnsignedPayload       string `json:"unsignedPayload"`
	SignablePayload       string `json:"signablePayload"`
	InputPayloadDigest    string `json:"inputPayloadDigest"`
	MetadataDigest        string `json:"metadataDigest"`
	IntermediateOutputB64 string `json:"intermediateOutputB64"`
	ExpectedMessage       string `json:"expectedMessage"`
}

func loadSolanaIntermediateSample(t *testing.T) (solanaIntermediateSample, []byte) {
	t.Helper()
	var s solanaIntermediateSample
	require.NoError(t, json.Unmarshal(testdata.SolanaIntermediateSampleJSON, &s))
	raw, err := base64.StdEncoding.DecodeString(s.IntermediateOutputB64)
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	return s, raw
}

// supportedSchemaVersions lists every schema_version
// DecodeSolanaIntermediateOutput decodes, so a test can run its case under each
// wire frame.
var supportedSchemaVersions = []uint16{SolanaIntermediateMinSchemaVersion, SolanaIntermediateMaxSchemaVersion}

// encodeFrame serializes body under version's wire frame: bare under 4; under 5
// with the JsonParsed decoder tag and maxFee as the trailing cap.
func encodeFrame(t *testing.T, version uint16, body solanaIntermediateBody, maxFee uint64) []byte {
	t.Helper()
	var raw []byte
	var err error
	switch version {
	case 4:
		raw, err = borsh.Serialize(solanaIntermediateFrameV4{SchemaVersion: version, Body: body})
	case 5:
		raw, err = borsh.Serialize(solanaIntermediateFrameV5{
			SchemaVersion:            version,
			NativeInstructionDecoder: SolanaNativeInstructionDecoderJSONParsed,
			Body:                     body,
			MaxFeeLamports:           maxFee,
		})
	default:
		t.Fatalf("no wire frame for schema_version %d", version)
	}
	require.NoError(t, err)
	return raw
}

// TestDecodeSolanaIntermediateOutput_RealSample decodes the Borsh bytes the
// local visualsign-parser produced and asserts the Go mirror matches the Rust
// layout: schema_version, populated account/program keys, and at least one
// instruction. This is the Go-vs-Rust cross-check for the decoder.
func TestDecodeSolanaIntermediateOutput_RealSample(t *testing.T) {
	_, raw := loadSolanaIntermediateSample(t)

	out, err := DecodeSolanaIntermediateOutput(raw)
	require.NoError(t, err)
	require.Equal(t, SolanaIntermediateSchemaVersion, out.SchemaVersion)
	require.NotEmpty(t, out.AccountKeys)
	require.NotEmpty(t, out.ProgramKeys)
	require.NotEmpty(t, out.Instructions)
	// Every account key in an instruction must be a non-empty base58 string.
	for _, ix := range out.Instructions {
		require.NotEmpty(t, ix.ProgramKey)
		for _, acc := range ix.Accounts {
			require.NotEmpty(t, acc.AccountKey)
		}
	}

	// The fixture is a native SOL transfer via the System Program. Assert the
	// concrete decoded values so a layout drift (wrong field order shifting
	// bytes) would fail, not just a structural check.
	require.Equal(t, "11111111111111111111111111111111", out.Instructions[0].ProgramKey)
	require.Len(t, out.Transfers, 1)
	require.Equal(t, "1000000000", out.Transfers[0].Amount)
	require.NotEqual(t, out.Transfers[0].From, out.Transfers[0].To)

	// A System transfer has no IDL match; since schema_version 4 the parser
	// fills parsed_instruction_data from its native decode instead (empty
	// IdlSource/IdlHash), alongside Solana's own jsonParsed decode.
	transfer := out.Instructions[0]
	require.Equal(t, RegisteredSourceNative, transfer.RegisteredSource)
	require.Nil(t, transfer.IdlParseError)
	require.Nil(t, transfer.SolanaJSONParseError)
	require.NotNil(t, transfer.ParsedInstructionData)
	require.Equal(t, "transfer", transfer.ParsedInstructionData.InstructionName)
	require.Equal(t, "02000000", transfer.ParsedInstructionData.Discriminator)
	require.Equal(t, map[string]string{
		"source":      out.Transfers[0].From,
		"destination": out.Transfers[0].To,
	}, transfer.ParsedInstructionData.NamedAccounts)
	require.Empty(t, transfer.ParsedInstructionData.IdlSource)
	require.Empty(t, transfer.ParsedInstructionData.IdlHash)
	require.NotNil(t, transfer.SolanaJSONParsedData)
	require.Equal(t, "system", transfer.SolanaJSONParsedData.Program)

	// The schema_version 5 frame: the dev build has the json-parsed feature
	// (the native decode above depends on it), and the request sent no cap,
	// so the trailing field holds the parser default. It is the last field: a
	// wrong length anywhere before it would misplace these eight bytes and
	// fail here.
	require.NotNil(t, out.NativeInstructionDecoder)
	require.Equal(t, SolanaNativeInstructionDecoderJSONParsed, *out.NativeInstructionDecoder)
	require.NotNil(t, out.MaxFeeLamports)
	require.Equal(t, SolanaDefaultMaxFeeLamports, *out.MaxFeeLamports)
}

// TestComputeBorshParsedTransactionPayloadHash_IntermediateCrosscheck pins the
// signed-message digest against the value the local parser's enclave signed for
// the same response. This proves the client's Borsh append of the intermediate
// output (u32-LE length prefix + raw bytes) matches the parser's
// signing_digest_bytes exactly — the invariant that keeps signature
// verification passing when intermediate output is requested.
func TestComputeBorshParsedTransactionPayloadHash_IntermediateCrosscheck(t *testing.T) {
	s, raw := loadSolanaIntermediateSample(t)

	got, err := ComputeBorshParsedTransactionPayloadHash(
		s.SignablePayload, s.InputPayloadDigest, s.MetadataDigest, raw)
	require.NoError(t, err)
	require.Equal(t, s.ExpectedMessage, got)

	// Sanity: omitting the intermediate bytes must produce a DIFFERENT digest,
	// confirming the append is actually part of the signed message.
	withoutIntermediate, err := ComputeBorshParsedTransactionPayloadHash(
		s.SignablePayload, s.InputPayloadDigest, s.MetadataDigest, nil)
	require.NoError(t, err)
	require.NotEqual(t, s.ExpectedMessage, withoutIntermediate)
}

// TestDecodeSolanaIntermediateOutput_SimulatedInstructions guards against
// SolanaSimulatedInstruction field-order drift vs the Rust struct. The
// fixture is a real mainnet Kamino Vault transaction (14 simulated inner
// instructions at the schema_version 5 re-simulation, 18 at the previous
// one: the count follows vault state, the first two calls do not), including
// CPIs into KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD decoded via the
// in-crate Kamino preset IDL merged into idl_records -- RegisteredSource::Preset,
// IdlSource "Preset" -- and RPC-parsed SPL Token/Token-2022 calls, which
// schema_version 4 also decodes natively. SolanaJSONParseError is the last
// per-instruction field, so a missing or misplaced field would shift every
// following instruction's bytes, and the trailing schema_version 5 cap
// would land on the wrong bytes.
func TestDecodeSolanaIntermediateOutput_SimulatedInstructions(t *testing.T) {
	var s solanaIntermediateSample
	require.NoError(t, json.Unmarshal(testdata.SolanaIntermediateSimulatedSampleJSON, &s))
	raw, err := base64.StdEncoding.DecodeString(s.IntermediateOutputB64)
	require.NoError(t, err)
	require.NotEmpty(t, raw)

	out, err := DecodeSolanaIntermediateOutput(raw)
	require.NoError(t, err)
	require.Nil(t, out.SimulationError, "the supplied simulation was read")
	require.Len(t, out.SimulatedInstructions, 14)
	require.NotNil(t, out.NativeInstructionDecoder)
	require.Equal(t, SolanaNativeInstructionDecoderJSONParsed, *out.NativeInstructionDecoder)
	require.NotNil(t, out.MaxFeeLamports)
	require.Equal(t, SolanaDefaultMaxFeeLamports, *out.MaxFeeLamports, "no cap was sent with the simulation")

	sim := out.SimulatedInstructions[0]
	require.EqualValues(t, 2, sim.Index)
	require.EqualValues(t, 2, sim.StackHeight)
	require.Equal(t, "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD", sim.ProgramKey)
	require.Equal(t, "906e1a67a2ccfc9301", sim.InstructionDataHex)
	require.Equal(t, RegisteredSourcePreset, sim.RegisteredSource)
	require.Len(t, sim.Accounts, 8)
	require.Equal(t, "FSMWJh3geL7dgeMauFWkjCpU2pvXocGpXcUpVsMQULki", sim.Accounts[0])
	require.Nil(t, sim.IdlParseError)
	require.NotNil(t, sim.ParsedInstructionData)
	require.Equal(t, "refreshReservesBatch", sim.ParsedInstructionData.InstructionName)
	require.Equal(t, "Preset", sim.ParsedInstructionData.IdlSource)
	require.Nil(t, sim.SolanaRpcParsedData)
	require.Nil(t, sim.SolanaJSONParseError, "None normalizes to nil")

	// An RPC-parsed Token-2022 transferChecked: the RPC consumed the data and
	// accounts, and the parser mapped its jsonParsed decode into a native
	// ParsedInstructionData (schema_version 4).
	rpcParsed := out.SimulatedInstructions[1]
	require.EqualValues(t, 2, rpcParsed.Index)
	require.Equal(t, "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", rpcParsed.ProgramKey)
	require.Equal(t, RegisteredSourceNative, rpcParsed.RegisteredSource)
	require.Empty(t, rpcParsed.Accounts)
	require.Empty(t, rpcParsed.InstructionDataHex)
	require.NotNil(t, rpcParsed.SolanaRpcParsedData)
	require.Equal(t, "spl-token", rpcParsed.SolanaRpcParsedData.Program)
	require.Nil(t, rpcParsed.IdlParseError)
	require.Nil(t, rpcParsed.SolanaJSONParseError)
	require.NotNil(t, rpcParsed.ParsedInstructionData)
	require.Equal(t, "transferChecked", rpcParsed.ParsedInstructionData.InstructionName)
	require.Equal(t, "0c", rpcParsed.ParsedInstructionData.Discriminator)
	require.Len(t, rpcParsed.ParsedInstructionData.NamedAccounts, 4)
	require.Contains(t, rpcParsed.ParsedInstructionData.NamedAccounts, "authority")
	require.Empty(t, rpcParsed.ParsedInstructionData.IdlSource)
	require.Empty(t, rpcParsed.ParsedInstructionData.IdlHash)

	for i, sim := range out.SimulatedInstructions {
		require.Nil(t, sim.SolanaJSONParseError, "simulated instruction %d decoded cleanly", i)
	}
}

// TestDecodeSolanaIntermediateOutput_SimulationError pins each
// SolanaSimulationError discriminant end-to-end through Borsh
// encode/decode/normalize under both frames, so a discriminant or
// normalizeOptionals bug (e.g. misreading a real error as None, or vice versa)
// fails a test instead of only ever being exercised by the untested success
// path, and a discriminant Rust does not declare is refused.
func TestDecodeSolanaIntermediateOutput_SimulationError(t *testing.T) {
	variants := []SolanaSimulationError{
		SolanaSimulationErrorInvalidBase64,
		SolanaSimulationErrorInvalidJSON,
		SolanaSimulationErrorSimulationFailed,
		SolanaSimulationErrorCallerIdlRecordsUnusable,
		SolanaSimulationErrorCompiledInstruction,
		SolanaSimulationErrorInvalidInstructionData,
		SolanaSimulationErrorSimulationUnsupported,
	}
	for _, version := range supportedSchemaVersions {
		for _, v := range variants {
			t.Run(fmt.Sprintf("v%d %s", version, v), func(t *testing.T) {
				v := v
				raw := encodeFrame(t, version, solanaIntermediateBody{SimulationError: &v}, 0)

				out, err := DecodeSolanaIntermediateOutput(raw)
				require.NoError(t, err)
				require.NotNil(t, out.SimulationError)
				require.Equal(t, v, *out.SimulationError)
			})
		}

		t.Run(fmt.Sprintf("v%d nil stays nil", version), func(t *testing.T) {
			out, err := DecodeSolanaIntermediateOutput(encodeFrame(t, version, solanaIntermediateBody{}, 0))
			require.NoError(t, err)
			require.Nil(t, out.SimulationError)
		})

		t.Run(fmt.Sprintf("v%d unknown discriminant is refused", version), func(t *testing.T) {
			eight := SolanaSimulationError(8)
			_, err := DecodeSolanaIntermediateOutput(encodeFrame(t, version, solanaIntermediateBody{SimulationError: &eight}, 0))
			require.ErrorContains(t, err, "unknown solana intermediate output simulation_error 8")
		})
	}
}

// TestDecodeSolanaIntermediateOutput_SchemaGuard ensures a schema_version
// outside the supported range is rejected rather than silently misdecoded,
// and that both ends of the range decode.
func TestDecodeSolanaIntermediateOutput_SchemaGuard(t *testing.T) {
	// A well-formed frame of the newest layout under the next version.
	future := encodeFrame(t, SolanaIntermediateMaxSchemaVersion, solanaIntermediateBody{}, 0)
	future[0], future[1] = byte(SolanaIntermediateMaxSchemaVersion+1), 0
	_, err := DecodeSolanaIntermediateOutput(future)
	require.ErrorContains(t, err, "unsupported solana intermediate output schema_version 6 (this client supports 4 through 5)")

	// Another version's bytes need not decode under any layout here; the
	// version must still be what's reported, not a byte-level Borsh error.
	for _, raw := range [][]byte{{3, 0}, {0, 0}, {0xff, 0xff}} {
		_, err = DecodeSolanaIntermediateOutput(raw)
		require.ErrorContains(t, err, "unsupported solana intermediate output schema_version", "%x", raw)
	}

	_, err = DecodeSolanaIntermediateOutput([]byte{5})
	require.ErrorContains(t, err, "too short for schema_version")

	for _, version := range supportedSchemaVersions {
		out, err := DecodeSolanaIntermediateOutput(encodeFrame(t, version, solanaIntermediateBody{}, 0))
		require.NoError(t, err)
		require.Equal(t, version, out.SchemaVersion)
	}
}

// TestDecodeSolanaIntermediateOutput_TrailingBytes pins the check Rust's
// borsh::from_slice makes and borsh-go does not: bytes after the end of the
// frame are refused. Without it a reader one field behind decodes a newer
// frame "successfully" and drops what it did not read, which for a
// schema_version 4 reader given a 5 frame is the cap.
func TestDecodeSolanaIntermediateOutput_TrailingBytes(t *testing.T) {
	_, real := loadSolanaIntermediateSample(t)
	for _, extra := range [][]byte{{0}, {1}, {0, 0, 0, 0, 0, 0, 0, 0}} {
		padded := append(append([]byte{}, real...), extra...)
		_, err := DecodeSolanaIntermediateOutput(padded)
		require.ErrorContains(t, err, "trailing bytes after its schema_version 5 frame", "%x appended to real parser output", extra)
	}

	for _, version := range supportedSchemaVersions {
		raw := encodeFrame(t, version, solanaIntermediateBody{AccountKeys: []string{"A1"}}, 5_105_000)
		_, err := DecodeSolanaIntermediateOutput(raw)
		require.NoError(t, err, "v%d frame", version)

		_, err = DecodeSolanaIntermediateOutput(append(raw, 0))
		require.ErrorContains(t, err, fmt.Sprintf("trailing bytes after its schema_version %d frame", version))

		_, err = DecodeSolanaIntermediateOutput(raw[:len(raw)-1])
		require.ErrorContains(t, err, "borsh-decode solana intermediate output", "v%d frame short by one byte", version)
	}
}

// TestDecodeSolanaIntermediateOutput_SchemaVersion4 decodes the previous
// layout, which a parser without #625 still emits. The schema_version 5 frame
// is that layout plus the decoder tag and the trailing cap: intermediate.rs
// intermediate_wire_identifies_native_decoder_capability pins the body's
// start at byte 3 and the cap in the last eight bytes, so the real 5 fixtures
// with those removed are the bytes a schema_version 4 parser emitted for the
// same transaction. A 4 output decodes with the two schema_version 5 fields
// nil and absent from the JSON output, and is held to the same trailing-bytes
// check.
func TestDecodeSolanaIntermediateOutput_SchemaVersion4(t *testing.T) {
	for name, fixture := range map[string][]byte{
		"transfer":  testdata.SolanaIntermediateSampleJSON,
		"simulated": testdata.SolanaIntermediateSimulatedSampleJSON,
	} {
		t.Run(name, func(t *testing.T) {
			var s solanaIntermediateSample
			require.NoError(t, json.Unmarshal(fixture, &s))
			v5, err := base64.StdEncoding.DecodeString(s.IntermediateOutputB64)
			require.NoError(t, err)
			fromV5, err := DecodeSolanaIntermediateOutput(v5)
			require.NoError(t, err)

			v4 := append([]byte{4, 0}, v5[3:len(v5)-8]...)
			out, err := DecodeSolanaIntermediateOutput(v4)
			require.NoError(t, err)
			require.EqualValues(t, 4, out.SchemaVersion)
			require.Nil(t, out.NativeInstructionDecoder)
			require.Nil(t, out.MaxFeeLamports)

			want := *fromV5
			want.SchemaVersion = 4
			want.NativeInstructionDecoder = nil
			want.MaxFeeLamports = nil
			require.Equal(t, &want, out, "the body decodes the same under both frames")

			encoded, err := json.Marshal(out)
			require.NoError(t, err)
			require.Contains(t, string(encoded), `"schemaVersion":4`)
			require.NotContains(t, string(encoded), `"nativeInstructionDecoder"`)
			require.NotContains(t, string(encoded), `"maxFeeLamports"`)

			_, err = DecodeSolanaIntermediateOutput(append(v4, 0))
			require.ErrorContains(t, err, "trailing bytes after its schema_version 4 frame")
		})
	}
}

// TestDecodeSolanaIntermediateOutput_UnknownDiscriminants refuses enum values
// this client cannot name, as Rust's deserializer does, instead of rendering
// them as e.g. "RegisteredSource(5)". borsh-go accepts any byte for a simple
// enum; it bounds-checks only the complex SolanaIdlParseError enum itself,
// which the last case shows.
func TestDecodeSolanaIntermediateOutput_UnknownDiscriminants(t *testing.T) {
	for _, version := range supportedSchemaVersions {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			raw := encodeFrame(t, version, solanaIntermediateBody{
				Instructions: []SolanaIntermediateInstruction{{ProgramKey: "p", RegisteredSource: RegisteredSource(5)}},
			}, 0)
			_, err := DecodeSolanaIntermediateOutput(raw)
			require.ErrorContains(t, err, "unknown solana intermediate output registered_source 5 on instruction 0")

			raw = encodeFrame(t, version, solanaIntermediateBody{
				SimulatedInstructions: []SolanaSimulatedInstruction{{ProgramKey: "p", RegisteredSource: RegisteredSource(5)}},
			}, 0)
			_, err = DecodeSolanaIntermediateOutput(raw)
			require.ErrorContains(t, err, "unknown solana intermediate output registered_source 5 on simulated instruction 0")

			// borsh-go refuses to serialize a complex enum tag that names no
			// field (and writes a variant's payload only when it is a struct),
			// so encode the DataParseError variant and raise its tag byte in
			// place: Some (01), tag (00), then the payload's first string.
			raw = encodeFrame(t, version, solanaIntermediateBody{
				Instructions: []SolanaIntermediateInstruction{{
					ProgramKey: "p",
					IdlParseError: &SolanaIdlParseError{Enum: 0, DataParseError: SolanaIdlDataOrAccountsError{
						InstructionName: "variant-marker", Error: "e",
					}},
				}},
			}, 0)
			marker := append([]byte{1, 0, 14, 0, 0, 0}, []byte("variant-marker")...)
			at := bytes.Index(raw, marker)
			require.NotEqual(t, -1, at, "Some(DataParseError) must be encoded once")
			raw[at+1] = 4
			_, err = DecodeSolanaIntermediateOutput(raw)
			require.ErrorContains(t, err, "borsh-decode solana intermediate output")
		})
	}
}

// TestDecodeSolanaIntermediateOutput_MaxFeeLamportsRoundTrip pins the
// schema_version 5 frame around the previous layout, as intermediate.rs
// intermediate_wire_identifies_native_decoder_capability and
// intermediate_output_round_trip_is_deterministic assert: the version leads,
// the native decoder tag follows it, the body opens with account_keys'
// length, and the cap trails. A caller cap round-trips through Borsh
// encode/decode, and output that stops where the cap should start -- a
// schema_version 4 body under a 5 header -- is refused rather than decoded
// with a zero cap.
func TestDecodeSolanaIntermediateOutput_MaxFeeLamportsRoundTrip(t *testing.T) {
	const callerCap uint64 = 5_105_000
	raw := encodeFrame(t, SolanaIntermediateMaxSchemaVersion, solanaIntermediateBody{
		Instructions: []SolanaIntermediateInstruction{
			{ProgramKey: "11111111111111111111111111111111", RegisteredSource: RegisteredSourceNative},
		},
	}, callerCap)
	require.Equal(t, []byte{5, 0}, raw[:2], "schema_version leads, little-endian u16")
	require.Equal(t, byte(1), raw[2], "native_instruction_decoder follows: JsonParsed")
	require.Equal(t, []byte{0, 0, 0, 0}, raw[3:7], "the body opens with account_keys' length")
	require.Equal(t, []byte{0x68, 0xe5, 0x4d, 0, 0, 0, 0, 0}, raw[len(raw)-8:], "max_fee_lamports trails, little-endian u64")

	out, err := DecodeSolanaIntermediateOutput(raw)
	require.NoError(t, err)
	require.NotNil(t, out.NativeInstructionDecoder)
	require.Equal(t, SolanaNativeInstructionDecoderJSONParsed, *out.NativeInstructionDecoder)
	require.NotNil(t, out.MaxFeeLamports)
	require.Equal(t, callerCap, *out.MaxFeeLamports)

	t.Run("body without the trailing cap is refused", func(t *testing.T) {
		_, err := DecodeSolanaIntermediateOutput(raw[:len(raw)-8])
		require.ErrorContains(t, err, "borsh-decode solana intermediate output")

		// The same cut on real parser output: the schema_version 4 layout
		// under a 5 header must not pass as a zero cap.
		_, real := loadSolanaIntermediateSample(t)
		_, err = DecodeSolanaIntermediateOutput(real[:len(real)-8])
		require.ErrorContains(t, err, "borsh-decode solana intermediate output")
	})
}

// TestDecodeSolanaIntermediateOutput_NativeInstructionDecoder pins the
// capability tag that schema_version 5 places right after the version: both
// variants round-trip with their Rust names in the JSON output, a tag this
// client cannot name is refused (as Rust's deserializer refuses an unknown
// discriminant), and output that ends before the tag is refused.
func TestDecodeSolanaIntermediateOutput_NativeInstructionDecoder(t *testing.T) {
	for _, tc := range []struct {
		decoder SolanaNativeInstructionDecoder
		tag     byte
		name    string
	}{
		{SolanaNativeInstructionDecoderComputeBudgetOnly, 0, "ComputeBudgetOnly"},
		{SolanaNativeInstructionDecoderJSONParsed, 1, "JsonParsed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := borsh.Serialize(solanaIntermediateFrameV5{
				SchemaVersion:            SolanaIntermediateMaxSchemaVersion,
				NativeInstructionDecoder: tc.decoder,
			})
			require.NoError(t, err)
			require.Equal(t, tc.tag, raw[2])

			out, err := DecodeSolanaIntermediateOutput(raw)
			require.NoError(t, err)
			require.NotNil(t, out.NativeInstructionDecoder)
			require.Equal(t, tc.decoder, *out.NativeInstructionDecoder)
			require.Equal(t, tc.name, out.NativeInstructionDecoder.String())

			encoded, err := json.Marshal(out)
			require.NoError(t, err)
			require.Contains(t, string(encoded), `"nativeInstructionDecoder":"`+tc.name+`"`)
		})
	}

	t.Run("unknown tag is refused", func(t *testing.T) {
		raw, err := borsh.Serialize(solanaIntermediateFrameV5{
			SchemaVersion:            SolanaIntermediateMaxSchemaVersion,
			NativeInstructionDecoder: SolanaNativeInstructionDecoder(2),
		})
		require.NoError(t, err)
		_, err = DecodeSolanaIntermediateOutput(raw)
		require.ErrorContains(t, err, "unknown solana intermediate output native_instruction_decoder 2")
	})

	t.Run("output that ends before the tag is refused", func(t *testing.T) {
		_, err := DecodeSolanaIntermediateOutput([]byte{5, 0})
		require.ErrorContains(t, err, "borsh-decode solana intermediate output")
	})
}

// TestDecodeSolanaIntermediateOutput_SolanaJSONParsed decodes real v5 parser
// output (testdata/solana_intermediate_json_parsed_sample.json) for a Compute
// Budget instruction plus a System transfer. Both are Native: since
// schema_version 4 each carries a native ParsedInstructionData (Compute
// Budget by the parser's own decoder, which Solana's jsonParsed lacks) next
// to SolanaJSONParsedData. The jsonParsed fields follow RegisteredSource, so
// a wrong field order would shift the bytes and fail. The schema_version 5
// frame carries the CLI build's JsonParsed decoder tag and, since the CLI was
// given no cap, the parser default.
func TestDecodeSolanaIntermediateOutput_SolanaJSONParsed(t *testing.T) {
	var s struct {
		IntermediateOutputHex string `json:"intermediateOutputHex"`
	}
	require.NoError(t, json.Unmarshal(testdata.SolanaIntermediateJSONParsedSampleJSON, &s))
	raw, err := hex.DecodeString(s.IntermediateOutputHex)
	require.NoError(t, err)

	out, err := DecodeSolanaIntermediateOutput(raw)
	require.NoError(t, err)
	require.Len(t, out.Instructions, 2)

	computeBudget := out.Instructions[0]
	require.Equal(t, "ComputeBudget111111111111111111111111111111", computeBudget.ProgramKey)
	require.Equal(t, RegisteredSourceNative, computeBudget.RegisteredSource)
	require.Nil(t, computeBudget.SolanaJSONParseError, "None normalizes to nil")
	require.Nil(t, computeBudget.IdlParseError)
	require.Equal(t, &SolanaJSONParsedInstructionDataIo{
		Program:    "compute-budget",
		ParsedJSON: `{"info":{"microLamports":5000},"type":"setComputeUnitPrice"}`,
	}, computeBudget.SolanaJSONParsedData)
	require.Equal(t, &SolanaParsedInstructionDataIo{
		InstructionName:     "setComputeUnitPrice",
		Discriminator:       "03",
		NamedAccounts:       map[string]string{},
		ProgramCallArgsJSON: `{"microLamports":5000}`,
	}, computeBudget.ParsedInstructionData)

	transfer := out.Instructions[1]
	require.Equal(t, "11111111111111111111111111111111", transfer.ProgramKey)
	require.Equal(t, RegisteredSourceNative, transfer.RegisteredSource)
	require.Nil(t, transfer.SolanaJSONParseError, "None normalizes to nil")
	require.Nil(t, transfer.IdlParseError)
	require.Equal(t, &SolanaJSONParsedInstructionDataIo{
		Program: "system",
		ParsedJSON: `{"info":{"destination":"8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR","lamports":1001,` +
			`"source":"4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"},"type":"transfer"}`,
	}, transfer.SolanaJSONParsedData)
	require.Equal(t, &SolanaParsedInstructionDataIo{
		InstructionName: "transfer",
		Discriminator:   "02000000",
		NamedAccounts: map[string]string{
			"destination": "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR",
			"source":      "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
		},
		ProgramCallArgsJSON: `{"destination":"8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR","lamports":1001,` +
			`"source":"4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"}`,
	}, transfer.ParsedInstructionData)
	require.Len(t, out.Transfers, 1)
	require.Equal(t, "1001", out.Transfers[0].Amount)
	require.NotNil(t, out.NativeInstructionDecoder)
	require.Equal(t, SolanaNativeInstructionDecoderJSONParsed, *out.NativeInstructionDecoder)
	require.NotNil(t, out.MaxFeeLamports)
	require.Equal(t, SolanaDefaultMaxFeeLamports, *out.MaxFeeLamports)
}

// TestDecodeSolanaIntermediateOutput_SolanaJSONParseErrorRoundTrip pins the
// SolanaJSONParseError marker, which no real fixture carries since v4 decodes
// every program in them: set and unset, on a top-level and on a simulated
// instruction (where it is the trailing v4 field), through Borsh
// encode/decode/normalize under both frames.
func TestDecodeSolanaIntermediateOutput_SolanaJSONParseErrorRoundTrip(t *testing.T) {
	unsupported := "program has no native decoder"
	mismatch := "System instruction key mismatch"
	body := solanaIntermediateBody{
		Instructions: []SolanaIntermediateInstruction{
			{ProgramKey: "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy", RegisteredSource: RegisteredSourceNative, SolanaJSONParseError: &unsupported},
			{ProgramKey: "11111111111111111111111111111111", RegisteredSource: RegisteredSourceNative},
		},
		SimulatedInstructions: []SolanaSimulatedInstruction{
			{Index: 0, StackHeight: 2, ProgramKey: "11111111111111111111111111111111", RegisteredSource: RegisteredSourceNative, SolanaJSONParseError: &mismatch},
			{Index: 0, StackHeight: 2, ProgramKey: "ComputeBudget111111111111111111111111111111", RegisteredSource: RegisteredSourceNative,
				ParsedInstructionData: &SolanaParsedInstructionDataIo{InstructionName: "setComputeUnitLimit", Discriminator: "02", ProgramCallArgsJSON: `{"units":200000}`}},
		},
	}
	for _, version := range supportedSchemaVersions {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			out, err := DecodeSolanaIntermediateOutput(encodeFrame(t, version, body, 0))
			require.NoError(t, err)
			require.Len(t, out.Instructions, 2)
			require.Equal(t, &unsupported, out.Instructions[0].SolanaJSONParseError)
			require.Nil(t, out.Instructions[0].ParsedInstructionData)
			require.Nil(t, out.Instructions[1].SolanaJSONParseError)

			require.Len(t, out.SimulatedInstructions, 2)
			require.Equal(t, &mismatch, out.SimulatedInstructions[0].SolanaJSONParseError)
			require.Nil(t, out.SimulatedInstructions[0].ParsedInstructionData)
			require.Nil(t, out.SimulatedInstructions[1].SolanaJSONParseError)
			require.NotNil(t, out.SimulatedInstructions[1].ParsedInstructionData)
			require.Equal(t, "setComputeUnitLimit", out.SimulatedInstructions[1].ParsedInstructionData.InstructionName)
		})
	}
}

// TestDecodeSolanaIntermediateOutput_SolanaJSONParsedRoundTrip covers the
// case the real samples don't: an instruction with neither jsonParsed field set.
func TestDecodeSolanaIntermediateOutput_SolanaJSONParsedRoundTrip(t *testing.T) {
	body := solanaIntermediateBody{
		Instructions: []SolanaIntermediateInstruction{
			{ProgramKey: "dapp", RegisteredSource: RegisteredSourceUnregistered},
		},
	}
	for _, version := range supportedSchemaVersions {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			out, err := DecodeSolanaIntermediateOutput(encodeFrame(t, version, body, 0))
			require.NoError(t, err)
			require.Nil(t, out.Instructions[0].SolanaJSONParsedData)
			require.Nil(t, out.Instructions[0].SolanaJSONParseError)
		})
	}
}
