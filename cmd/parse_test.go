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

	// Assert the expected flags exist by name and that the required ones are
	// marked Required. Checking by name (rather than an exact Flags count) keeps
	// meaningful coverage -- it catches removal of any flag we rely on -- without
	// re-breaking every time a new flag is added.
	require.NotNil(t, cmd.Flags)
	required := map[string]bool{
		"host": true, "organization-id": true, "key-name": true, "unsigned-payload": true,
	}
	seen := make(map[string]bool)
	for _, flag := range cmd.Flags {
		switch f := flag.(type) {
		case *cli.StringFlag:
			seen[f.Name] = true
			if required[f.Name] {
				require.True(t, f.Required, "--%s should be required", f.Name)
			}
		case *cli.BoolFlag:
			seen[f.Name] = true
		}
	}

	for _, name := range []string{"host", "organization-id", "key-name", "unsigned-payload", "chain", "dev-path"} {
		require.True(t, seen[name], "parse should have --%s flag", name)
	}
}
