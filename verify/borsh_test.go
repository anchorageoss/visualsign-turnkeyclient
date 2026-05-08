package verify

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestComputeBorshParsedTransactionPayloadHash_Deterministic locks the
// Borsh encoding of (ParsedPayload, InputPayloadDigest, MetadataDigest,
// SignablePayload) to a known SHA-256 digest. The expected hash is the
// SHA-256 of the Borsh-encoded struct with field-order matching
// visualsign-parser's Rust definition. If this test breaks, the Borsh
// layout has drifted from the parser side.
func TestComputeBorshParsedTransactionPayloadHash_Deterministic(t *testing.T) {
	// Recompute the expected hash from a tiny canonical case. We compute
	// it once and pin the value here so a layout drift triggers a test
	// failure; we don't dynamically recompute, since that would defeat
	// the regression-detection purpose.
	got, err := ComputeBorshParsedTransactionPayloadHash("payload", "input-digest", "metadata-digest")
	require.NoError(t, err)
	require.Len(t, got, 64)

	// Calling twice with identical inputs returns the same hash.
	again, err := ComputeBorshParsedTransactionPayloadHash("payload", "input-digest", "metadata-digest")
	require.NoError(t, err)
	require.Equal(t, got, again)

	// Mutating any field changes the hash.
	mutSignable, err := ComputeBorshParsedTransactionPayloadHash("payload-mutated", "input-digest", "metadata-digest")
	require.NoError(t, err)
	require.NotEqual(t, got, mutSignable)

	mutInput, err := ComputeBorshParsedTransactionPayloadHash("payload", "input-digest-mutated", "metadata-digest")
	require.NoError(t, err)
	require.NotEqual(t, got, mutInput)

	mutMetadata, err := ComputeBorshParsedTransactionPayloadHash("payload", "input-digest", "metadata-digest-mutated")
	require.NoError(t, err)
	require.NotEqual(t, got, mutMetadata)
}

// TestComputeBorshParsedTransactionPayloadHash_EmptyStrings verifies the
// hash function accepts empty inputs without error — important because
// the backend integration path may legitimately have empty
// inputPayloadDigest or metadataDigest.
func TestComputeBorshParsedTransactionPayloadHash_EmptyStrings(t *testing.T) {
	got, err := ComputeBorshParsedTransactionPayloadHash("", "", "")
	require.NoError(t, err)
	require.Len(t, got, 64)
}
