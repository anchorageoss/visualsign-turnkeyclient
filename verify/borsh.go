package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/near/borsh-go"
)

// parsedTransactionPayload mirrors visualsign-parser's Rust struct. Field
// declaration order matters — Borsh serializes in declaration order, so
// this layout must stay in sync with the parser side. v2 reuses
// SignablePayload as ParsedPayload; the upstream parser at
// src/parser/app/src/routes/parse.rs is the source of truth.
type parsedTransactionPayload struct {
	ParsedPayload      string
	InputPayloadDigest string
	MetadataDigest     string
	SignablePayload    string
}

// ComputeBorshParsedTransactionPayloadHash recomputes the SHA-256 of the
// Borsh-encoded ParsedTransactionPayload — what the enclave signs as
// AppAttestation.Message. Compare the result against the reported
// AppAttestation.Message to bind that signed digest to the response's
// (signablePayload, inputPayloadDigest, metadataDigest); without this
// binding, an attacker who controls the transport could substitute
// signablePayload while keeping a valid signature over an unrelated
// message.
//
// intermediateOutput is the raw (already base64-decoded) bytes of the parser's
// optional machine-readable intermediate output. The proto field carrying it is
// #[borsh(skip)], so the four-field derived encoding is unchanged; when the
// field is non-empty the parser appends its Borsh Vec<u8> encoding (u32-LE
// length prefix followed by the raw bytes) to the signed bytes. We reproduce
// that here so the message binding stays valid when intermediate output is
// present. Pass nil/empty to get the byte-for-byte pre-feature digest — the
// signing path is out-of-band (no tag byte), so an empty value matches the
// legacy four-field encoding exactly.
func ComputeBorshParsedTransactionPayloadHash(signablePayload, inputDigest, metadataDigest string, intermediateOutput []byte) (string, error) {
	raw, err := borsh.Serialize(parsedTransactionPayload{
		ParsedPayload:      signablePayload,
		InputPayloadDigest: inputDigest,
		MetadataDigest:     metadataDigest,
		SignablePayload:    signablePayload,
	})
	if err != nil {
		return "", fmt.Errorf("borsh serialize ParsedTransactionPayload: %w", err)
	}
	if len(intermediateOutput) > 0 {
		// borsh.Serialize of a []byte is Borsh Vec<u8>: u32-LE length prefix
		// followed by the raw bytes — matching the parser's
		// borsh::to_vec(&intermediate_output) append.
		appended, err := borsh.Serialize(intermediateOutput)
		if err != nil {
			return "", fmt.Errorf("borsh serialize intermediate output: %w", err)
		}
		raw = append(raw, appended...)
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}
