package verify

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf8"
)

// Decoder for the NEAR "intermediate output" — the machine-readable structured
// decode the visualsign-parser emits alongside the human-readable
// SignablePayload. The upstream source of truth is visualsign-parser's
// src/chain_parsers/visualsign-near/src/intermediate.rs, with a second mirror
// in C++ at source/c/hsm/vsp/near_intermediate_output.* in the anchorage
// monorepo.
//
// Hand-decoded rather than routed through borsh-go, which the Solana mirror in
// intermediate.go uses. Three reasons, only the first tied to the pinned
// version:
//
//  1. borsh-go v0.3.1 cannot express Option faithfully. At borsh.go:216 it
//     decodes a None into a non-nil pointer to the zero value, so None and
//     Some(zero) come back identical. Solana tolerates that because its
//     optionals are never a degenerate Some -- intermediate.go says as much.
//     NEAR's NonceIndex is not: a gas key's first nonce is index 0, and the
//     field exists precisely so two different gas-key nonces do not look like
//     the same nonce.
//  2. borsh-go accepts trailing bytes, decoding a longer payload from a newer
//     schema as a valid shorter one -- the failure SchemaVersion exists to
//     catch, and cannot catch when the version field itself did not move.
//  3. borsh-go reads any non-zero Option tag as Some, so a corrupt 0xff
//     decodes as a present value rather than as an error.
//
// Reason 1 expires on a bump: an untagged commit after v0.3.1 returns nil for
// None, with byte-identical encoding. Reasons 2 and 3 do not, and both are
// silent acceptance -- the failure mode a consensus-critical decoder can least
// afford. Whoever bumps should narrow this comment rather than delete the
// reader, and should revisit normalizeOptionals in intermediate.go, whose
// stated justification is reason 1.
//
// Borsh is not self-describing, so the reads below must follow the Rust types
// field-for-field in declaration order.

// NearIntermediateSchemaVersion is the schema_version this client understands.
// It matches NEAR_INTERMEDIATE_SCHEMA_VERSION in the parser's intermediate.rs
// and hsm::vsp::near::SCHEMA_VERSION in the C++ mirror.
const NearIntermediateSchemaVersion uint16 = 1

// NearEnvelopeKind names which of the three things a NEAR signature covers.
type NearEnvelopeKind string

const (
	NearEnvelopeTransaction NearEnvelopeKind = "Transaction"
	NearEnvelopeNep413      NearEnvelopeKind = "Nep413"
	NearEnvelopeRawMessage  NearEnvelopeKind = "RawMessage"
)

// NearActionKind names which action variant an entry carries.
type NearActionKind string

const (
	NearActionFunctionCall NearActionKind = "FunctionCall"
	NearActionTransfer     NearActionKind = "Transfer"
	// NearActionOther is an action kind the schema does not model in full. It
	// names the kind and carries the action's own Borsh bytes, so a policy sees
	// that an action it does not model is present and can refuse, rather than
	// not seeing it.
	NearActionOther NearActionKind = "Other"
)

// NearIntermediateOutput mirrors intermediate.rs NearIntermediateOutput.
type NearIntermediateOutput struct {
	SchemaVersion uint16 `json:"schemaVersion"`
	// Network is the canonical network identifier the payload was validated
	// against, not a caller-supplied spelling.
	Network  string         `json:"network"`
	Envelope NearEnvelopeIo `json:"envelope"`
}

// NearEnvelopeIo mirrors intermediate.rs NearEnvelopeIo. Exactly one of the
// pointers is set, named by Kind.
type NearEnvelopeIo struct {
	Kind        NearEnvelopeKind   `json:"kind"`
	Transaction *NearTransactionIo `json:"transaction,omitempty"`
	Nep413      *NearNep413Io      `json:"nep413,omitempty"`
	RawMessage  *NearRawMessageIo  `json:"rawMessage,omitempty"`
}

// NearTransactionIo mirrors intermediate.rs NearTransactionIo.
type NearTransactionIo struct {
	SignerID string `json:"signerId"`
	// PublicKey is `ed25519:<base58>`, the form NEAR prints a public key in.
	PublicKey string `json:"publicKey"`
	Nonce     uint64 `json:"nonce"`
	// NonceIndex is set only for a gas key, whose nonce is indexed, and nil for
	// an ordinary access key. Some(0) is a real value and is not conflated with
	// absence.
	NonceIndex *uint16 `json:"nonceIndex,omitempty"`
	ReceiverID string  `json:"receiverId"`
	// BlockHash is base58, as NEAR prints a block hash.
	BlockHash string         `json:"blockHash"`
	Actions   []NearActionIo `json:"actions"`
}

// NearActionIo mirrors intermediate.rs NearActionIo. Exactly one of the
// pointers is set, named by Kind.
type NearActionIo struct {
	Kind         NearActionKind      `json:"kind"`
	FunctionCall *NearFunctionCallIo `json:"functionCall,omitempty"`
	Transfer     *NearTransferIo     `json:"transfer,omitempty"`
	Other        *NearOtherActionIo  `json:"other,omitempty"`
}

// NearFunctionCallIo mirrors intermediate.rs NearFunctionCallIo.
type NearFunctionCallIo struct {
	MethodName string `json:"methodName"`
	// ArgsHex is the argument bytes exactly as signed, and is always present:
	// ArgsJSON is a re-encoding, so a policy that needs certainty reads this.
	ArgsHex string `json:"argsHex"`
	// ArgsJSON is the arguments as canonical JSON, keys alphabetized at every
	// nesting level. Empty when the arguments are not JSON.
	ArgsJSON string `json:"argsJson"`
	Gas      uint64 `json:"gas"`
	// Deposit is yocto-NEAR as a decimal string: a NEAR deposit is a u128 and
	// Borsh has no canonical primitive for that width.
	Deposit string `json:"deposit"`
}

// NearTransferIo mirrors intermediate.rs NearTransferIo.
type NearTransferIo struct {
	// Deposit is yocto-NEAR as a decimal string.
	Deposit string `json:"deposit"`
}

// NearOtherActionIo mirrors intermediate.rs NearOtherActionIo.
type NearOtherActionIo struct {
	// Kind is the near_primitives variant name.
	Kind string `json:"kind"`
	// BorshHex is the action as NEAR serializes it, so nothing about the
	// transaction is hidden from a policy that allowlists the kinds it models.
	BorshHex string `json:"borshHex"`
}

// NearNep413Io mirrors intermediate.rs Nep413Io: an off-chain message envelope.
// NEP-413 wraps an arbitrary message, so the envelope says who the message is
// for without saying what it does -- which is why Recipient and Nonce are the
// fields a policy binds a sign-in to.
type NearNep413Io struct {
	Recipient string `json:"recipient"`
	// NonceBase64 is the 32-byte nonce, base64 -- the encoding NEP-413 uses.
	NonceBase64 string  `json:"nonceBase64"`
	CallbackURL *string `json:"callbackUrl,omitempty"`
	Message     string  `json:"message"`
}

// NearRawMessageIo mirrors intermediate.rs RawMessageIo: a message signed over
// its own bytes, with no envelope around it.
type NearRawMessageIo struct {
	Message string `json:"message"`
}

// DecodeNearIntermediateOutput decodes the raw Borsh bytes of the parser's NEAR
// intermediate output. It rejects any schema_version other than the one this
// client mirrors, so a parser-side layout change surfaces as an explicit error
// rather than a silently misdecoded struct, and it rejects trailing bytes, so a
// longer payload from a newer schema cannot decode as a valid shorter one.
func DecodeNearIntermediateOutput(b []byte) (*NearIntermediateOutput, error) {
	r := &borshReader{buf: b}

	version, err := r.u16()
	if err != nil {
		return nil, fmt.Errorf("near intermediate output: schema version: %w", err)
	}
	if version != NearIntermediateSchemaVersion {
		return nil, fmt.Errorf(
			"unsupported near intermediate output schema_version %d (this client supports %d)",
			version, NearIntermediateSchemaVersion)
	}
	out := &NearIntermediateOutput{SchemaVersion: version}
	if out.Network, err = r.string(); err != nil {
		return nil, fmt.Errorf("near intermediate output: network: %w", err)
	}
	if out.Envelope, err = r.envelope(); err != nil {
		return nil, fmt.Errorf("near intermediate output: envelope: %w", err)
	}
	if r.remaining() != 0 {
		return nil, fmt.Errorf(
			"near intermediate output: %d trailing bytes after a complete decode", r.remaining())
	}
	return out, nil
}

type borshReader struct {
	buf []byte
	at  int
}

func (r *borshReader) remaining() int { return len(r.buf) - r.at }

func (r *borshReader) take(n int) ([]byte, error) {
	if n < 0 || r.remaining() < n {
		return nil, fmt.Errorf("want %d bytes, have %d", n, r.remaining())
	}
	b := r.buf[r.at : r.at+n]
	r.at += n
	return b, nil
}

func (r *borshReader) u8() (byte, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *borshReader) u16() (uint16, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (r *borshReader) u32() (uint32, error) {
	b, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (r *borshReader) u64() (uint64, error) {
	b, err := r.take(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

// string reads a Borsh String: a u32 length prefix then that many UTF-8 bytes.
// The length is checked against what remains before allocating, so a corrupt
// prefix fails rather than reserving gigabytes.
func (r *borshReader) string() (string, error) {
	n, err := r.u32()
	if err != nil {
		return "", err
	}
	if n > math.MaxInt32 {
		return "", fmt.Errorf("string length %d is implausible", n)
	}
	b, err := r.take(int(n))
	if err != nil {
		return "", fmt.Errorf("string of %d bytes: %w", n, err)
	}
	// Rust's borsh decodes String through String::from_utf8 and rejects
	// invalid sequences, so accepting them here would make this decoder a
	// superset of the producer -- the fourth silent acceptance this file
	// exists to avoid. It matters downstream too: json.Marshal replaces
	// invalid bytes with U+FFFD, so a rendered field would differ from the
	// bytes that were signed.
	if !utf8.Valid(b) {
		return "", fmt.Errorf("string of %d bytes is not valid UTF-8", n)
	}
	return string(b), nil
}

// option reads a Borsh Option tag: 0 for None, 1 for Some. Any other byte is a
// corrupt stream rather than a variant this decoder does not know.
func (r *borshReader) option() (bool, error) {
	tag, err := r.u8()
	if err != nil {
		return false, err
	}
	switch tag {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("option tag must be 0 or 1, got %d", tag)
	}
}

func (r *borshReader) optionalU16() (*uint16, error) {
	some, err := r.option()
	if err != nil || !some {
		return nil, err
	}
	v, err := r.u16()
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (r *borshReader) optionalString() (*string, error) {
	some, err := r.option()
	if err != nil || !some {
		return nil, err
	}
	v, err := r.string()
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (r *borshReader) envelope() (NearEnvelopeIo, error) {
	var out NearEnvelopeIo
	tag, err := r.u8()
	if err != nil {
		return out, err
	}
	switch tag {
	case 0:
		tx, err := r.transaction()
		if err != nil {
			return out, err
		}
		out.Kind, out.Transaction = NearEnvelopeTransaction, &tx
	case 1:
		nep, err := r.nep413()
		if err != nil {
			return out, err
		}
		out.Kind, out.Nep413 = NearEnvelopeNep413, &nep
	case 2:
		msg, err := r.string()
		if err != nil {
			return out, err
		}
		out.Kind, out.RawMessage = NearEnvelopeRawMessage, &NearRawMessageIo{Message: msg}
	default:
		return out, fmt.Errorf("unknown envelope variant %d", tag)
	}
	return out, nil
}

func (r *borshReader) transaction() (NearTransactionIo, error) {
	var tx NearTransactionIo
	var err error
	if tx.SignerID, err = r.string(); err != nil {
		return tx, fmt.Errorf("signer_id: %w", err)
	}
	if tx.PublicKey, err = r.string(); err != nil {
		return tx, fmt.Errorf("public_key: %w", err)
	}
	if tx.Nonce, err = r.u64(); err != nil {
		return tx, fmt.Errorf("nonce: %w", err)
	}
	if tx.NonceIndex, err = r.optionalU16(); err != nil {
		return tx, fmt.Errorf("nonce_index: %w", err)
	}
	if tx.ReceiverID, err = r.string(); err != nil {
		return tx, fmt.Errorf("receiver_id: %w", err)
	}
	if tx.BlockHash, err = r.string(); err != nil {
		return tx, fmt.Errorf("block_hash: %w", err)
	}
	count, err := r.u32()
	if err != nil {
		return tx, fmt.Errorf("actions length: %w", err)
	}
	// The cheapest encodable action is 5 bytes: a variant tag plus an empty
	// u32-prefixed string. A count larger than what that allows is corrupt.
	const minEncodedActionBytes = 5
	if uint64(count) > uint64(r.remaining()/minEncodedActionBytes) {
		return tx, fmt.Errorf("actions length %d exceeds the %d bytes remaining", count, r.remaining())
	}
	// The bound above limits the count; it does not limit the allocation, and
	// a NearActionIo is far wider than its smallest encoding. Cap the hint and
	// let append grow -- the loop is already bounded, so this costs a
	// reallocation rather than admitting an amplified reservation.
	tx.Actions = make([]NearActionIo, 0, min(int(count), 256))
	for i := range count {
		action, err := r.action()
		if err != nil {
			return tx, fmt.Errorf("action %d: %w", i, err)
		}
		tx.Actions = append(tx.Actions, action)
	}
	return tx, nil
}

func (r *borshReader) action() (NearActionIo, error) {
	var out NearActionIo
	tag, err := r.u8()
	if err != nil {
		return out, err
	}
	switch tag {
	case 0:
		var fc NearFunctionCallIo
		if fc.MethodName, err = r.string(); err != nil {
			return out, fmt.Errorf("method_name: %w", err)
		}
		if fc.ArgsHex, err = r.string(); err != nil {
			return out, fmt.Errorf("args_hex: %w", err)
		}
		if fc.ArgsJSON, err = r.string(); err != nil {
			return out, fmt.Errorf("args_json: %w", err)
		}
		if fc.Gas, err = r.u64(); err != nil {
			return out, fmt.Errorf("gas: %w", err)
		}
		if fc.Deposit, err = r.string(); err != nil {
			return out, fmt.Errorf("deposit: %w", err)
		}
		out.Kind, out.FunctionCall = NearActionFunctionCall, &fc
	case 1:
		deposit, err := r.string()
		if err != nil {
			return out, fmt.Errorf("deposit: %w", err)
		}
		out.Kind, out.Transfer = NearActionTransfer, &NearTransferIo{Deposit: deposit}
	case 2:
		var other NearOtherActionIo
		if other.Kind, err = r.string(); err != nil {
			return out, fmt.Errorf("kind: %w", err)
		}
		if other.BorshHex, err = r.string(); err != nil {
			return out, fmt.Errorf("borsh_hex: %w", err)
		}
		out.Kind, out.Other = NearActionOther, &other
	default:
		return out, fmt.Errorf("unknown action variant %d", tag)
	}
	return out, nil
}

func (r *borshReader) nep413() (NearNep413Io, error) {
	var nep NearNep413Io
	var err error
	if nep.Recipient, err = r.string(); err != nil {
		return nep, fmt.Errorf("recipient: %w", err)
	}
	if nep.NonceBase64, err = r.string(); err != nil {
		return nep, fmt.Errorf("nonce_base64: %w", err)
	}
	if nep.CallbackURL, err = r.optionalString(); err != nil {
		return nep, fmt.Errorf("callback_url: %w", err)
	}
	if nep.Message, err = r.string(); err != nil {
		return nep, fmt.Errorf("message: %w", err)
	}
	return nep, nil
}
