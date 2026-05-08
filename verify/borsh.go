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
func ComputeBorshParsedTransactionPayloadHash(signablePayload, inputDigest, metadataDigest string) (string, error) {
	raw, err := borsh.Serialize(parsedTransactionPayload{
		ParsedPayload:      signablePayload,
		InputPayloadDigest: inputDigest,
		MetadataDigest:     metadataDigest,
		SignablePayload:    signablePayload,
	})
	if err != nil {
		return "", fmt.Errorf("borsh serialize ParsedTransactionPayload: %w", err)
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}
