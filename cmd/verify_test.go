package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

func TestVerifyCommand(t *testing.T) {
	cmd := VerifyCommand()

	require.NotNil(t, cmd)
	require.Equal(t, "verify", cmd.Name)
	require.NotEmpty(t, cmd.Usage)

	// Verify required flags exist
	require.NotNil(t, cmd.Flags)
	require.Greater(t, len(cmd.Flags), 0)

	// Check for specific required flags
	var hasHost, hasOrgID, hasKeyName, hasPayload bool
	for _, flag := range cmd.Flags {
		switch f := flag.(type) {
		case *cli.StringFlag:
			if f.Name == "host" {
				hasHost = true
			}
			if f.Name == "organization-id" {
				hasOrgID = true
			}
			if f.Name == "key-name" {
				hasKeyName = true
			}
			if f.Name == "unsigned-payload" {
				hasPayload = true
			}
		}
	}

	require.True(t, hasHost, "Should have --host flag")
	require.True(t, hasOrgID, "Should have --organization-id flag")
	require.True(t, hasKeyName, "Should have --key-name flag")
	require.True(t, hasPayload, "Should have --unsigned-payload flag")
}

func TestMatchedHashLabel(t *testing.T) {
	require.Equal(t, "Raw manifest hash", matchedHashLabel("raw"))
	require.Equal(t, "Reserialized manifest hash", matchedHashLabel("reserialized"))
	require.Equal(t, "Canonical JSON manifest hash", matchedHashLabel("canonical"))
	require.Equal(t, "Envelope hash", matchedHashLabel("envelope"))
	// A JSON envelope match must never be labeled as a raw-manifest match:
	// isJSONEnvelope gating in processManifest means "canonical" is the
	// only value it can ever produce, but this guards the label mapping
	// itself against silently defaulting to the wrong (or a misleading)
	// label for any unrecognized value.
	require.NotEqual(t, matchedHashLabel("raw"), matchedHashLabel("canonical"))
	require.Equal(t, "Manifest hash", matchedHashLabel(""))
}

func TestVerifyCommandHasDevPathFlag(t *testing.T) {
	cmd := VerifyCommand()

	var hasDevPath bool
	for _, flag := range cmd.Flags {
		if f, ok := flag.(*cli.BoolFlag); ok && f.Name == "dev-path" {
			hasDevPath = true
		}
	}

	require.True(t, hasDevPath, "verify should have a --dev-path flag to target /visualsign-dev")
}
