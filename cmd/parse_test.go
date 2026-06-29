package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

func TestParseCommand(t *testing.T) {
	cmd := ParseCommand()

	require.NotNil(t, cmd)
	require.Equal(t, "parse", cmd.Name)
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
				require.True(t, f.Required)
			}
			if f.Name == "organization-id" {
				hasOrgID = true
				require.True(t, f.Required)
			}
			if f.Name == "key-name" {
				hasKeyName = true
				require.True(t, f.Required)
			}
			if f.Name == "unsigned-payload" {
				hasPayload = true
				require.True(t, f.Required)
			}
		}
	}

	require.True(t, hasHost)
	require.True(t, hasOrgID)
	require.True(t, hasKeyName)
	require.True(t, hasPayload)
}
