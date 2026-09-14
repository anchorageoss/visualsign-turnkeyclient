package verify

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// Bytes produced by the parser's own Rust types, not by this package. To
// regenerate after a schema change, run the test at
// src/chain_parsers/visualsign-near/tests/near_io_truth.rs in visualsign-parser,
// which prints hex(NearIntermediateOutput::to_bytes()) for these same inputs.
const (
	// A transaction with one of each action kind: a function call, a transfer,
	// and an AddKey the schema does not model in full.
	nearTxFixture = "01000c0000004e4541525f4d41494e4e4554000a000000616c6963652e6e65617234000000656432353531393a38" +
		"7256767448574672386861736451474744355769514254797234694832727545505056666a34393152504e070000" +
		"00000000000009000000777261702e6e656172200000003131313131313131313131313131313131313131313131" +
		"31313131313131313103000000001000000066745f7472616e736665725f63616c6c1a0000003762323236323232" +
		"3361333232633232363132323361333137640d0000007b2261223a312c2262223a327d00e057eb481b0000010000" +
		"00310102000000343202060000004164644b65795600000030353030373461666661373161623033306434303066" +
		"64666131626564303333646661366664336165333466393264313763303436656265333638653830643533373531" +
		"303030303030303030303030303030303031"
	// A NEP-413 envelope carrying a callback URL, so the Option::Some path is
	// covered alongside the None in the transaction above.
	nearNep413Fixture = "01000c0000004e4541525f544553544e4554010c000000696e74656e74732e6e6561722c00000058566f4b666d53" +
		"636233472b587148396b652f66536c4a2f33784f3539734e6843786870473832314248383d011600000068747470" +
		"733a2f2f6578616d706c652e636f6d2f6362070000005369676e20696e"
	nearRawMessageFixture = "01000c0000004e4541525f4d41494e4e455402070000007061796c6f6164"
)

func decodeFixture(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestDecodeNearIntermediateOutput_Transaction(t *testing.T) {
	out, err := DecodeNearIntermediateOutput(decodeFixture(t, nearTxFixture))
	require.NoError(t, err)

	require.Equal(t, NearIntermediateSchemaVersion, out.SchemaVersion)
	require.Equal(t, "NEAR_MAINNET", out.Network)
	require.Equal(t, NearEnvelopeTransaction, out.Envelope.Kind)
	require.Nil(t, out.Envelope.Nep413)
	require.Nil(t, out.Envelope.RawMessage)

	tx := out.Envelope.Transaction
	require.NotNil(t, tx)
	require.Equal(t, "alice.near", tx.SignerID)
	require.Equal(t, "ed25519:8rVvtHWFr8hasdQGGD5WiQBTyr4iH2ruEPPVfj491RPN", tx.PublicKey)
	require.Equal(t, uint64(7), tx.Nonce)
	require.Nil(t, tx.NonceIndex, "an ordinary access key has no nonce index")
	require.Equal(t, "wrap.near", tx.ReceiverID)
	require.Len(t, tx.Actions, 3)

	call := tx.Actions[0]
	require.Equal(t, NearActionFunctionCall, call.Kind)
	require.Equal(t, "ft_transfer_call", call.FunctionCall.MethodName)
	// The hex is the signed truth; the JSON is a re-encoding, alphabetized at
	// every level, so the two differ for input that was not already sorted.
	require.Equal(t, hex.EncodeToString([]byte(`{"b":2,"a":1}`)), call.FunctionCall.ArgsHex)
	require.Equal(t, `{"a":1,"b":2}`, call.FunctionCall.ArgsJSON)
	require.Equal(t, uint64(30_000_000_000_000), call.FunctionCall.Gas)
	require.Equal(t, "1", call.FunctionCall.Deposit)

	require.Equal(t, NearActionTransfer, tx.Actions[1].Kind)
	require.Equal(t, "42", tx.Actions[1].Transfer.Deposit)

	// An action this schema does not model is named and carried whole, so a
	// policy allowlisting the kinds it understands refuses it rather than not
	// seeing it.
	require.Equal(t, NearActionOther, tx.Actions[2].Kind)
	require.Equal(t, "AddKey", tx.Actions[2].Other.Kind)
	require.NotEmpty(t, tx.Actions[2].Other.BorshHex)
}

func TestDecodeNearIntermediateOutput_Nep413(t *testing.T) {
	out, err := DecodeNearIntermediateOutput(decodeFixture(t, nearNep413Fixture))
	require.NoError(t, err)

	require.Equal(t, "NEAR_TESTNET", out.Network)
	require.Equal(t, NearEnvelopeNep413, out.Envelope.Kind)
	nep := out.Envelope.Nep413
	require.NotNil(t, nep)
	require.Equal(t, "intents.near", nep.Recipient)
	require.Equal(t, "XVoKfmScb3G+XqH9ke/fSlJ/3xO59sNhCxhpG821BH8=", nep.NonceBase64)
	require.NotNil(t, nep.CallbackURL)
	require.Equal(t, "https://example.com/cb", *nep.CallbackURL)
	require.Equal(t, "Sign in", nep.Message)
}

func TestDecodeNearIntermediateOutput_RawMessage(t *testing.T) {
	out, err := DecodeNearIntermediateOutput(decodeFixture(t, nearRawMessageFixture))
	require.NoError(t, err)
	require.Equal(t, NearEnvelopeRawMessage, out.Envelope.Kind)
	require.NotNil(t, out.Envelope.RawMessage)
	require.Equal(t, "payload", out.Envelope.RawMessage.Message)
}

// nonceIndexTagOffset is where the transaction's Option<u16> nonce_index tag
// sits in nearTxFixture: 2 (schema) + 4+12 (network) + 1 (envelope tag)
// + 4+10 (signer_id) + 4+52 (public_key) + 8 (nonce).
const nonceIndexTagOffset = 2 + 4 + 12 + 1 + 4 + 10 + 4 + 52 + 8

// TestDecodeNearIntermediateOutput_SomeZeroNonceIndexIsNotNone is the reason
// this decoder is hand-written rather than routed through borsh-go, which
// decodes Option::None into a non-nil pointer to the zero value and so cannot
// tell None from Some(0). A gas key's first nonce is index 0, and the field
// exists so two different gas-key nonces do not read as the same nonce.
func TestDecodeNearIntermediateOutput_SomeZeroNonceIndexIsNotNone(t *testing.T) {
	none := decodeFixture(t, nearTxFixture)
	require.Equal(t, byte(0), none[nonceIndexTagOffset], "fixture must start with None here")

	// Splice Some(0) in place of None: tag 1 followed by a little-endian zero.
	someZero := make([]byte, 0, len(none)+2)
	someZero = append(someZero, none[:nonceIndexTagOffset]...)
	someZero = append(someZero, 0x01, 0x00, 0x00)
	someZero = append(someZero, none[nonceIndexTagOffset+1:]...)

	decodedNone, err := DecodeNearIntermediateOutput(none)
	require.NoError(t, err)
	decodedSome, err := DecodeNearIntermediateOutput(someZero)
	require.NoError(t, err)

	require.Nil(t, decodedNone.Envelope.Transaction.NonceIndex)
	require.NotNil(t, decodedSome.Envelope.Transaction.NonceIndex,
		"Some(0) must not decode as absent")
	require.Equal(t, uint16(0), *decodedSome.Envelope.Transaction.NonceIndex)
}

func TestDecodeNearIntermediateOutput_Rejections(t *testing.T) {
	valid := decodeFixture(t, nearRawMessageFixture)

	t.Run("a schema version this client does not mirror", func(t *testing.T) {
		bumped := append([]byte(nil), valid...)
		bumped[0] = 2
		_, err := DecodeNearIntermediateOutput(bumped)
		require.ErrorContains(t, err, "unsupported near intermediate output schema_version 2")
	})

	// A longer payload from a newer schema must not decode as a valid shorter
	// one: the prefix would parse and the extra bytes would go unnoticed.
	t.Run("trailing bytes", func(t *testing.T) {
		_, err := DecodeNearIntermediateOutput(append(append([]byte(nil), valid...), 0xff))
		require.ErrorContains(t, err, "trailing bytes")
	})

	t.Run("truncated", func(t *testing.T) {
		_, err := DecodeNearIntermediateOutput(valid[:len(valid)-3])
		require.Error(t, err)
	})

	t.Run("empty", func(t *testing.T) {
		_, err := DecodeNearIntermediateOutput(nil)
		require.Error(t, err)
	})

	t.Run("an envelope variant this client does not know", func(t *testing.T) {
		unknown := append([]byte(nil), valid...)
		unknown[18] = 9
		_, err := DecodeNearIntermediateOutput(unknown)
		require.ErrorContains(t, err, "unknown envelope variant 9")
	})

	// A corrupt length prefix must fail rather than drive a huge allocation.
	t.Run("an implausible string length", func(t *testing.T) {
		bad := append([]byte(nil), valid...)
		bad[19], bad[20], bad[21], bad[22] = 0xff, 0xff, 0xff, 0xff
		_, err := DecodeNearIntermediateOutput(bad)
		require.Error(t, err)
	})
}

// FuzzDecodeNearIntermediateOutput asserts the decoder never panics, however
// malformed its input. It reads a length-prefixed, self-describing format from
// bytes the parser produced but the transport could have corrupted, so every
// length and tag in the stream is attacker-influenceable in principle: an
// out-of-range slice or an unbounded allocation here would be reachable from a
// mangled response rather than only from a parser bug.
//
// A successful decode is additionally required to be faithful: re-reading what
// was decoded must consume every byte, which is what the trailing-byte check
// inside the decoder promises.
func FuzzDecodeNearIntermediateOutput(f *testing.F) {
	for _, seed := range []string{nearTxFixture, nearNep413Fixture, nearRawMessageFixture} {
		raw, err := hex.DecodeString(seed)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	// A bare version prefix, the shortest input that gets past the first gate.
	f.Add([]byte{0x01, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := DecodeNearIntermediateOutput(data)
		if err != nil {
			if out != nil {
				t.Fatalf("a failed decode must not return a value, got %+v", out)
			}
			return
		}
		if out.SchemaVersion != NearIntermediateSchemaVersion {
			t.Fatalf("decoded a version the gate should have refused: %d", out.SchemaVersion)
		}
		switch out.Envelope.Kind {
		case NearEnvelopeTransaction:
			if out.Envelope.Transaction == nil {
				t.Fatal("transaction envelope without a transaction")
			}
		case NearEnvelopeNep413:
			if out.Envelope.Nep413 == nil {
				t.Fatal("nep413 envelope without a payload")
			}
		case NearEnvelopeRawMessage:
			if out.Envelope.RawMessage == nil {
				t.Fatal("raw-message envelope without a message")
			}
		default:
			t.Fatalf("decoded an envelope kind that does not exist: %q", out.Envelope.Kind)
		}
	})
}
