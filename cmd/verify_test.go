package cmd

import (
	"context"
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
	require.Equal(t, "Canonical JSON manifest hash", matchedHashLabel("canonical"))
	// A JSON envelope match must never be labeled as a raw-manifest match:
	// processManifest only produces "canonical" when an envelope is present,
	// but this guards the label mapping
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

func TestVerifyCommandRejectsAPIVersionV1(t *testing.T) {
	err := VerifyCommand().Run(context.Background(), []string{
		"verify",
		"--host", "https://example.invalid",
		"--organization-id", "org",
		"--key-name", "key",
		"--unsigned-payload", "payload",
		"--chain", "CHAIN_SOLANA",
		"--api-version", "v1",
	})
	require.ErrorContains(t, err, `only "v2" is supported`)
}
