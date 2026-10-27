package verify

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	borsh "github.com/near/borsh-go"
	"github.com/stretchr/testify/require"

	"github.com/anchorageoss/visualsign-turnkeyclient/testdata"
)

const (
	schemaV4 uint16 = 4
	schemaV5 uint16 = 5
)

// encodeSolanaIntermediateOutput is the test-side inverse of
// DecodeSolanaIntermediateOutput: Borsh-encode the struct (which yields the
// schema_version 4 field layout, NativeInstructionDecoder being borsh_skip),
// then, for schema_version 5, insert the native_instruction_decoder byte
// after schema_version as the parser does.
func encodeSolanaIntermediateOutput(t *testing.T, in SolanaIntermediateOutput) []byte {
	t.Helper()
	raw, err := borsh.Serialize(in)
	require.NoError(t, err)
	if in.SchemaVersion < solanaNativeInstructionDecoderSince {
		require.Nil(t, in.NativeInstructionDecoder, "schema_version %d has no native_instruction_decoder", in.SchemaVersion)
		return raw
	}
	require.NotNil(t, in.NativeInstructionDecoder, "schema_version %d requires native_instruction_decoder", in.SchemaVersion)
	out := append([]byte{}, raw[:2]...)
	out = append(out, byte(*in.NativeInstructionDecoder))
	return append(out, raw[2:]...)
}

// minimalSolanaIntermediateOutput is an otherwise empty output of the given
// schema_version (with a JsonParsed decoder from 5 on).
func minimalSolanaIntermediateOutput(version uint16, simErr *SolanaSimulationError) SolanaIntermediateOutput {
	out := SolanaIntermediateOutput{SchemaVersion: version, SimulationError: simErr}
	if version >= solanaNativeInstructionDecoderSince {
		d := SolanaNativeInstructionDecoderJSONParsed
		out.NativeInstructionDecoder = &d
	}
	return out
}

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

// TestDecodeSolanaIntermediateOutput_RealSample decodes the Borsh bytes the
// local visualsign-parser produced and asserts the Go mirror matches the Rust
// layout: schema_version, populated account/program keys, and at least one
// instruction. This is the Go-vs-Rust cross-check for the decoder.
func TestDecodeSolanaIntermediateOutput_RealSample(t *testing.T) {
	_, raw := loadSolanaIntermediateSample(t)

	out, err := DecodeSolanaIntermediateOutput(raw)
	require.NoError(t, err)
	require.Equal(t, schemaV4, out.SchemaVersion)
	require.Nil(t, out.NativeInstructionDecoder)
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
// fixture is a real mainnet Kamino Vault transaction (18 simulated inner
// instructions, including CPIs into KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD
// decoded via the in-crate Kamino preset IDL merged into idl_records --
// RegisteredSource::Preset, IdlSource "Preset" -- and RPC-parsed SPL
// Token/Token-2022 calls, which schema_version 4 also decodes natively).
// SolanaJSONParseError is the last field, so a missing or misplaced field
// would shift every following instruction's bytes.
func TestDecodeSolanaIntermediateOutput_SimulatedInstructions(t *testing.T) {
	var s solanaIntermediateSample
	require.NoError(t, json.Unmarshal(testdata.SolanaIntermediateSimulatedSampleJSON, &s))
	raw, err := base64.StdEncoding.DecodeString(s.IntermediateOutputB64)
	require.NoError(t, err)
	require.NotEmpty(t, raw)

	out, err := DecodeSolanaIntermediateOutput(raw)
	require.NoError(t, err)
	require.Len(t, out.SimulatedInstructions, 18)

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
// encode/decode/normalize, so a discriminant or normalizeOptionals bug (e.g.
// misreading a real error as None, or vice versa) fails a test instead of
// only ever being exercised by the untested success path.
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
	// Pin the discriminants to the Rust enum's explicit values.
	for i, v := range variants {
		require.EqualValues(t, i+1, v, v.String())
	}
	require.Equal(t, "SimulationUnsupported", SolanaSimulationErrorSimulationUnsupported.String())

	for _, version := range []uint16{schemaV4, schemaV5} {
		for _, v := range variants {
			t.Run(fmt.Sprintf("v%d/%s", version, v), func(t *testing.T) {
				v := v
				raw := encodeSolanaIntermediateOutput(t, minimalSolanaIntermediateOutput(version, &v))

				out, err := DecodeSolanaIntermediateOutput(raw)
				require.NoError(t, err)
				require.NotNil(t, out.SimulationError)
				require.Equal(t, v, *out.SimulationError)
			})
		}

		t.Run(fmt.Sprintf("v%d/nil stays nil", version), func(t *testing.T) {
			raw := encodeSolanaIntermediateOutput(t, minimalSolanaIntermediateOutput(version, nil))

			out, err := DecodeSolanaIntermediateOutput(raw)
			require.NoError(t, err)
			require.Nil(t, out.SimulationError)
		})
	}
}

// TestDecodeSolanaIntermediateOutput_SchemaGuard ensures a schema_version
// outside SolanaIntermediateMinSchemaVersion..SolanaIntermediateMaxSchemaVersion
// is rejected rather than silently misdecoded.
func TestDecodeSolanaIntermediateOutput_SchemaGuard(t *testing.T) {
	require.Equal(t, uint16(4), SolanaIntermediateMinSchemaVersion)
	require.Equal(t, uint16(5), SolanaIntermediateMaxSchemaVersion)
	require.Equal(t, SolanaIntermediateMaxSchemaVersion, SolanaIntermediateSchemaVersion, //nolint:staticcheck // pins the deprecated alias
		"the deprecated single version names the newest mirrored version")

	for _, v := range []uint16{0, 3, 6, 0xffff} {
		t.Run(fmt.Sprintf("v%d", v), func(t *testing.T) {
			// A well-formed output body under either mirrored layout must
			// still be refused on the version alone.
			for _, layoutVersion := range []uint16{schemaV4, schemaV5} {
				raw := encodeSolanaIntermediateOutput(t, minimalSolanaIntermediateOutput(layoutVersion, nil))
				binary.LittleEndian.PutUint16(raw, v)
				_, err := DecodeSolanaIntermediateOutput(raw)
				require.EqualError(t, err, fmt.Sprintf(
					"unsupported solana intermediate output schema_version %d (this client supports 4 through 5)", v))
			}

			// Another version's bytes need not decode under any mirrored
			// layout; the version must still be what's reported, not a
			// byte-level Borsh error.
			raw := make([]byte, 2)
			binary.LittleEndian.PutUint16(raw, v)
			_, err := DecodeSolanaIntermediateOutput(raw)
			require.ErrorContains(t, err, fmt.Sprintf("unsupported solana intermediate output schema_version %d ", v))
		})
	}

	_, err := DecodeSolanaIntermediateOutput([]byte{4})
	require.ErrorContains(t, err, "too short for schema_version")
}

// TestDecodeSolanaIntermediateOutput_SolanaJSONParsed decodes real v4 parser
// output (testdata/solana_intermediate_json_parsed_sample.json) for a Compute
// Budget instruction plus a System transfer. Both are Native: since
// schema_version 4 each carries a native ParsedInstructionData (Compute
// Budget by the parser's own decoder, which Solana's jsonParsed lacks) next
// to SolanaJSONParsedData. The jsonParsed fields follow RegisteredSource, so
// a wrong field order would shift the bytes and fail.
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
}

// TestDecodeSolanaIntermediateOutput_SolanaJSONParseErrorRoundTrip pins the
// SolanaJSONParseError marker, which no real fixture carries since v4 decodes
// every program in them: set and unset, on a top-level and on a simulated
// instruction (where it is the trailing v4 field), through Borsh
// encode/decode/normalize.
func TestDecodeSolanaIntermediateOutput_SolanaJSONParseErrorRoundTrip(t *testing.T) {
	unsupported := "program has no native decoder"
	mismatch := "System instruction key mismatch"
	in := SolanaIntermediateOutput{
		SchemaVersion: schemaV4,
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
	raw, err := borsh.Serialize(in)
	require.NoError(t, err)

	out, err := DecodeSolanaIntermediateOutput(raw)
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
}

// TestDecodeSolanaIntermediateOutput_SolanaJSONParsedRoundTrip covers the
// case the real samples don't: an instruction with neither jsonParsed field set.
func TestDecodeSolanaIntermediateOutput_SolanaJSONParsedRoundTrip(t *testing.T) {
	in := SolanaIntermediateOutput{
		SchemaVersion: schemaV4,
		Instructions: []SolanaIntermediateInstruction{
			{ProgramKey: "dapp", RegisteredSource: RegisteredSourceUnregistered},
		},
	}
	raw, err := borsh.Serialize(in)
	require.NoError(t, err)

	out, err := DecodeSolanaIntermediateOutput(raw)
	require.NoError(t, err)
	require.Nil(t, out.Instructions[0].SolanaJSONParsedData)
	require.Nil(t, out.Instructions[0].SolanaJSONParseError)
}

// TestDecodeSolanaIntermediateOutput_SchemaVersions decodes each accepted
// schema_version with its own layout: 4 carries no native_instruction_decoder,
// 5 carries it immediately after schema_version.
func TestDecodeSolanaIntermediateOutput_SchemaVersions(t *testing.T) {
	in := SolanaIntermediateOutput{
		AccountKeys:     []string{"4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"},
		ProgramKeys:     []string{"11111111111111111111111111111111"},
		RecentBlockhash: "11111111111111111111111111111111",
		Instructions: []SolanaIntermediateInstruction{
			{ProgramKey: "11111111111111111111111111111111", RegisteredSource: RegisteredSourceNative},
		},
	}

	t.Run("v4", func(t *testing.T) {
		v4 := in
		v4.SchemaVersion = schemaV4
		raw := encodeSolanaIntermediateOutput(t, v4)
		require.Equal(t, []byte{4, 0, 1, 0, 0, 0}, raw[:6], "account_keys length follows schema_version directly")

		out, err := DecodeSolanaIntermediateOutput(raw)
		require.NoError(t, err)
		require.Equal(t, schemaV4, out.SchemaVersion)
		require.Nil(t, out.NativeInstructionDecoder)
		require.Equal(t, in.AccountKeys, out.AccountKeys)
		require.Equal(t, in.RecentBlockhash, out.RecentBlockhash)
		require.Len(t, out.Instructions, 1)

		js, err := json.Marshal(out)
		require.NoError(t, err)
		require.NotContains(t, string(js), "nativeInstructionDecoder")
	})

	t.Run("v5", func(t *testing.T) {
		v5 := in
		v5.SchemaVersion = schemaV5
		d := SolanaNativeInstructionDecoderComputeBudgetOnly
		v5.NativeInstructionDecoder = &d
		raw := encodeSolanaIntermediateOutput(t, v5)
		require.Equal(t, []byte{5, 0, 0, 1, 0, 0, 0}, raw[:7], "native_instruction_decoder sits between schema_version and account_keys")

		out, err := DecodeSolanaIntermediateOutput(raw)
		require.NoError(t, err)
		require.Equal(t, schemaV5, out.SchemaVersion)
		require.NotNil(t, out.NativeInstructionDecoder)
		require.Equal(t, SolanaNativeInstructionDecoderComputeBudgetOnly, *out.NativeInstructionDecoder)
		require.Equal(t, in.AccountKeys, out.AccountKeys)
		require.Equal(t, in.RecentBlockhash, out.RecentBlockhash)
		require.Len(t, out.Instructions, 1)

		js, err := json.Marshal(out)
		require.NoError(t, err)
		require.Contains(t, string(js), `"nativeInstructionDecoder":"ComputeBudgetOnly"`)
	})
}

// TestDecodeSolanaIntermediateOutput_NativeInstructionDecoder round-trips
// each native_instruction_decoder tag through encode/decode and refuses a
// tag the parser's enum does not define.
func TestDecodeSolanaIntermediateOutput_NativeInstructionDecoder(t *testing.T) {
	cases := []struct {
		tag  byte
		want SolanaNativeInstructionDecoder
		name string
	}{
		{0, SolanaNativeInstructionDecoderComputeBudgetOnly, "ComputeBudgetOnly"},
		{1, SolanaNativeInstructionDecoderJSONParsed, "JsonParsed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.EqualValues(t, tc.tag, tc.want)
			require.Equal(t, tc.name, tc.want.String())
			js, err := json.Marshal(tc.want)
			require.NoError(t, err)
			require.JSONEq(t, fmt.Sprintf("%q", tc.name), string(js))

			d := tc.want
			in := SolanaIntermediateOutput{SchemaVersion: schemaV5, NativeInstructionDecoder: &d}
			raw := encodeSolanaIntermediateOutput(t, in)
			require.Equal(t, tc.tag, raw[2])

			out, err := DecodeSolanaIntermediateOutput(raw)
			require.NoError(t, err)
			require.NotNil(t, out.NativeInstructionDecoder)
			require.Equal(t, tc.want, *out.NativeInstructionDecoder)
		})
	}

	t.Run("unknown tag refused", func(t *testing.T) {
		raw := encodeSolanaIntermediateOutput(t, minimalSolanaIntermediateOutput(schemaV5, nil))
		raw[2] = 2
		_, err := DecodeSolanaIntermediateOutput(raw)
		require.EqualError(t, err, "unknown solana intermediate output native_instruction_decoder tag 2")
		require.Equal(t, "SolanaNativeInstructionDecoder(2)", SolanaNativeInstructionDecoder(2).String())
	})
}

// TestDecodeSolanaIntermediateOutput_V5Truncation refuses schema_version 5
// output that ends exactly where native_instruction_decoder should be, and
// output that ends right after it.
func TestDecodeSolanaIntermediateOutput_V5Truncation(t *testing.T) {
	_, err := DecodeSolanaIntermediateOutput([]byte{5, 0})
	require.EqualError(t, err,
		"solana intermediate output schema_version 5 too short for native_instruction_decoder: 2 bytes")

	raw := encodeSolanaIntermediateOutput(t, minimalSolanaIntermediateOutput(schemaV5, nil))
	_, err = DecodeSolanaIntermediateOutput(raw[:3])
	require.ErrorContains(t, err, "borsh-decode solana intermediate output")

	// A schema_version 4 output of the same length is a plain Borsh
	// truncation, not a missing decoder byte.
	_, err = DecodeSolanaIntermediateOutput([]byte{4, 0})
	require.ErrorContains(t, err, "borsh-decode solana intermediate output")
}

// solanaV5Capture is one entry of testdata/solana_intermediate_v5_captures.json.
type solanaV5Capture struct {
	Name                           string          `json:"name"`
	UnsignedPayload                string          `json:"unsignedPayload"`
	V4ControlIntermediateOutputB64 string          `json:"v4ControlIntermediateOutputB64"`
	GatewayResponse                json.RawMessage `json:"gatewayResponse"`
}

func loadSolanaV5Captures(t *testing.T) []solanaV5Capture {
	t.Helper()
	var f struct {
		Cases []solanaV5Capture `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(testdata.SolanaIntermediateV5CapturesJSON, &f))
	require.Len(t, f.Cases, 3)
	return f.Cases
}

// v5IntermediateOutput extracts the base64 intermediate output from a
// capture's gateway response.
func (c solanaV5Capture) v5IntermediateOutput(t *testing.T) []byte {
	t.Helper()
	var r struct {
		Response struct {
			ParsedTransaction struct {
				Payload struct {
					IntermediateOutput string `json:"intermediateOutput"`
				} `json:"payload"`
			} `json:"parsedTransaction"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(c.GatewayResponse, &r))
	raw, err := base64.StdEncoding.DecodeString(r.Response.ParsedTransaction.Payload.IntermediateOutput)
	require.NoError(t, err)
	return raw
}

// TestDecodeSolanaIntermediateOutput_RealV5Captures decodes real schema_version
// 5 output from parser PR #575 and its schema_version 4 control for the same
// transaction. Apart from the version and the decoder byte the wire bytes are
// identical, so the two decodes must agree on every other field.
func TestDecodeSolanaIntermediateOutput_RealV5Captures(t *testing.T) {
	for _, c := range loadSolanaV5Captures(t) {
		t.Run(c.Name, func(t *testing.T) {
			v5raw := c.v5IntermediateOutput(t)
			v4raw, err := base64.StdEncoding.DecodeString(c.V4ControlIntermediateOutputB64)
			require.NoError(t, err)
			require.Equal(t, []byte{5, 0, 1}, v5raw[:3], "schema_version 5, JsonParsed")
			require.Equal(t, []byte{4, 0}, v4raw[:2])
			require.Equal(t, v4raw[2:], v5raw[3:], "layout after the decoder byte is unchanged")

			v5, err := DecodeSolanaIntermediateOutput(v5raw)
			require.NoError(t, err)
			require.Equal(t, schemaV5, v5.SchemaVersion)
			require.NotNil(t, v5.NativeInstructionDecoder)
			require.Equal(t, SolanaNativeInstructionDecoderJSONParsed, *v5.NativeInstructionDecoder)
			require.NotEmpty(t, v5.AccountKeys)
			require.NotEmpty(t, v5.Instructions)
			require.NotEmpty(t, v5.RecentBlockhash)
			for _, ix := range v5.Instructions {
				require.NotEmpty(t, ix.ProgramKey)
			}

			v4, err := DecodeSolanaIntermediateOutput(v4raw)
			require.NoError(t, err)
			require.Equal(t, schemaV4, v4.SchemaVersion)
			require.Nil(t, v4.NativeInstructionDecoder)

			v5.SchemaVersion, v5.NativeInstructionDecoder = v4.SchemaVersion, nil
			require.Equal(t, v4, v5)
		})
	}
}
