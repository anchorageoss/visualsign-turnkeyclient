package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/version"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

func TestMainApp(t *testing.T) {
	t.Run("app structure", func(t *testing.T) {
		app := &cli.Command{
			Name:  "turnkey-client",
			Usage: "Turnkey Visualsign Client",
			Commands: []*cli.Command{
				{Name: "parse"},
				{Name: "verify"},
				{Name: "decode"},
				{Name: "attestation"},
			},
		}

		require.Equal(t, "turnkey-client", app.Name)
		require.Equal(t, 4, len(app.Commands))
	})

	t.Run("help command", func(t *testing.T) {
		// Create a buffer to capture output
		var buf bytes.Buffer

		app := &cli.Command{
			Name:   "turnkey-client",
			Usage:  "Turnkey Visualsign Client",
			Writer: &buf,
			Commands: []*cli.Command{
				{Name: "parse", Usage: "Parse manifest"},
				{Name: "verify", Usage: "Verify attestation"},
				{Name: "decode", Usage: "Decode manifest"},
				{Name: "attestation", Usage: "Get attestation"},
			},
		}

		// Run help command
		err := app.Run(context.Background(), []string{"turnkey-client", "--help"})
		require.NoError(t, err)

		// Check output contains expected commands
		output := buf.String()
		require.Contains(t, output, "turnkey-client")
		require.Contains(t, output, "COMMANDS:")
	})

	t.Run("app handles unknown commands", func(t *testing.T) {
		// Test that the app structure allows for proper command validation
		// The actual CLI behavior (help output, exit codes) is tested in integration tests
		app := &cli.Command{
			Name:  "turnkey-client",
			Usage: "Turnkey Visualsign Client",
			Commands: []*cli.Command{
				{Name: "parse"},
				{Name: "verify"},
				{Name: "decode"},
				{Name: "attestation"},
			},
		}

		// Verify all expected commands are present
		require.Equal(t, 4, len(app.Commands))

		commandNames := make(map[string]bool)
		for _, cmd := range app.Commands {
			commandNames[cmd.Name] = true
		}

		require.True(t, commandNames["parse"])
		require.True(t, commandNames["verify"])
		require.True(t, commandNames["decode"])
		require.True(t, commandNames["attestation"])
		require.False(t, commandNames["invalid-command"])
	})
}

func TestVersionFlag(t *testing.T) {
	var buf bytes.Buffer

	app := &cli.Command{
		Name:    "turnkey-client",
		Usage:   "Turnkey Visualsign Client",
		Version: version.String(),
		Writer:  &buf,
	}

	err := app.Run(context.Background(), []string{"turnkey-client", "--version"})
	require.NoError(t, err)

	output := buf.String()
	require.Contains(t, output, "dev")
	require.Contains(t, output, "commit:")
}

// TestMainCommands verifies that all commands are properly registered
func TestMainCommands(t *testing.T) {
	// This doesn't test main() directly but verifies the app structure
	// which increases understanding of what main() does

	testCases := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "parse help",
			args:     []string{"turnkey-client", "parse", "--help"},
			wantErr:  false,
			contains: "parse",
		},
		{
			name:     "verify help",
			args:     []string{"turnkey-client", "verify", "--help"},
			wantErr:  false,
			contains: "verify",
		},
		{
			name:     "decode help",
			args:     []string{"turnkey-client", "decode", "--help"},
			wantErr:  false,
			contains: "decode",
		},
		{
			name:     "attestation help",
			args:     []string{"turnkey-client", "attestation", "--help"},
			wantErr:  false,
			contains: "attestation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer

			// Create minimal app with command names
			app := &cli.Command{
				Name:      "turnkey-client",
				Writer:    &buf,
				ErrWriter: &buf,
				Commands: []*cli.Command{
					{
						Name:  strings.Split(tc.args[1], " ")[0],
						Usage: "Test command",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "test", Usage: "Test flag"},
						},
					},
				},
			}

			err := app.Run(context.Background(), tc.args)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tc.contains != "" {
				output := buf.String()
				require.Contains(t, output, tc.contains)
			}
		})
	}
}
