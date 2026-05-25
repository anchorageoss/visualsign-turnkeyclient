package verify

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestComputeBorshParsedTransactionPayloadHash_PinnedDigests pins SHA-256
// of the Borsh-encoded ParsedTransactionPayload for canonical inputs and
// confirms each field contributes to the hash. If a pinned digest breaks,
// the Borsh layout has drifted from visualsign-parser's Rust struct (or
// borsh-go changed) and the parser/client sides no longer agree on what
// AppAttestation.Message should be.
func TestComputeBorshParsedTransactionPayloadHash_PinnedDigests(t *testing.T) {
	const (
		baseSignable        = "payload"
		baseInputDigest     = "input-digest"
		baseMetadataDigest  = "metadata-digest"
		baseExpectedDigest  = "9a56e437a67222b2ef3ba1f175d55055667dc43747bdbf9bad6a1304df5dbd63"
		emptyExpectedDigest = "374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb"
	)

	pinned := []struct {
		name                                        string
		signable, inputDigest, metadataDigest, want string
	}{
		{"canonical", baseSignable, baseInputDigest, baseMetadataDigest, baseExpectedDigest},
		{"all empty", "", "", "", emptyExpectedDigest},
	}
	for _, tc := range pinned {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ComputeBorshParsedTransactionPayloadHash(tc.signable, tc.inputDigest, tc.metadataDigest)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	mutations := []struct {
		name                                  string
		signable, inputDigest, metadataDigest string
	}{
		{"signable mutated", baseSignable + "-mutated", baseInputDigest, baseMetadataDigest},
		{"input digest mutated", baseSignable, baseInputDigest + "-mutated", baseMetadataDigest},
		{"metadata digest mutated", baseSignable, baseInputDigest, baseMetadataDigest + "-mutated"},
	}
	for _, tc := range mutations {
		t.Run(tc.name+" differs from canonical", func(t *testing.T) {
			got, err := ComputeBorshParsedTransactionPayloadHash(tc.signable, tc.inputDigest, tc.metadataDigest)
			require.NoError(t, err)
			require.NotEqual(t, baseExpectedDigest, got)
		})
	}
}
