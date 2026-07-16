package verify

import (
	"encoding/base64"
	"encoding/json"
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

	// A System transfer has no IDL match, so parsed_instruction_data is
	// Option::None — normalized back to a nil pointer (not an empty object).
	require.Nil(t, out.Instructions[0].ParsedInstructionData)
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

// TestDecodeSolanaIntermediateOutput_SchemaGuard ensures an unexpected
// schema_version is rejected rather than silently misdecoded.
func TestDecodeSolanaIntermediateOutput_SchemaGuard(t *testing.T) {
	// A minimal, well-formed SolanaIntermediateOutput with a bumped version.
	future := SolanaIntermediateOutput{SchemaVersion: SolanaIntermediateSchemaVersion + 1}
	raw, err := borsh.Serialize(future)
	require.NoError(t, err)

	_, err = DecodeSolanaIntermediateOutput(raw)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported solana intermediate output schema_version")
}
