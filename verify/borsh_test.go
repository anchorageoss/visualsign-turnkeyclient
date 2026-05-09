package verify

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestComputeBorshParsedTransactionPayloadHash_PinnedDigest pins the
// SHA-256 of the Borsh-encoded ParsedTransactionPayload to a known
// constant for a canonical input. If this test breaks, the Borsh layout
// has drifted from visualsign-parser's Rust definition (or borsh-go has
// changed encoding behavior) and the parser/client sides will no longer
// agree on what AppAttestation.Message should be.
func TestComputeBorshParsedTransactionPayloadHash_PinnedDigest(t *testing.T) {
	const expected = "9a56e437a67222b2ef3ba1f175d55055667dc43747bdbf9bad6a1304df5dbd63"
	got, err := ComputeBorshParsedTransactionPayloadHash("payload", "input-digest", "metadata-digest")
	require.NoError(t, err)
	require.Equal(t, expected, got)

	// Calling twice with identical inputs returns the same hash.
	again, err := ComputeBorshParsedTransactionPayloadHash("payload", "input-digest", "metadata-digest")
	require.NoError(t, err)
	require.Equal(t, got, again)

	// Mutating any field changes the hash — guards against the unlikely
	// case that two distinct field permutations collide on a fixed
	// 32-byte SHA-256.
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

// TestComputeBorshParsedTransactionPayloadHash_EmptyStrings pins the
// hash for all-empty inputs — important because the backend integration
// path may legitimately have empty inputPayloadDigest or metadataDigest.
func TestComputeBorshParsedTransactionPayloadHash_EmptyStrings(t *testing.T) {
	const expected = "374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb"
	got, err := ComputeBorshParsedTransactionPayloadHash("", "", "")
	require.NoError(t, err)
	require.Equal(t, expected, got)
}
