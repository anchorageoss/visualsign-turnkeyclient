package cmd

import (
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

func TestDecodeCommand(t *testing.T) {
	cmd := DecodeCommand()

	require.NotNil(t, cmd)
	require.Equal(t, "decode-manifest", cmd.Name)
	require.Len(t, cmd.Commands, 2)
}

func TestDecodeRawManifestCommand(t *testing.T) {
	cmd := decodeRawManifestCommand()

	require.NotNil(t, cmd)
	require.Equal(t, "raw", cmd.Name)
	require.Len(t, cmd.Flags, 4)

	// Verify flags
	var hasFile, hasBase64, hasJSON bool
	for _, flag := range cmd.Flags {
		switch f := flag.(type) {
		case *cli.StringFlag:
			if f.Name == "file" {
				hasFile = true
			}
			if f.Name == "base64" {
				hasBase64 = true
			}
		case *cli.BoolFlag:
			if f.Name == "json" {
				hasJSON = true
			}
		}
	}

	require.True(t, hasFile)
	require.True(t, hasBase64)
	require.True(t, hasJSON)
}

func TestDecodeManifestEnvelopeCommand(t *testing.T) {
	cmd := decodeManifestEnvelopeCommand()

	require.NotNil(t, cmd)
	require.Equal(t, "envelope", cmd.Name)

	// Check flags exist
	require.Len(t, cmd.Flags, 4)
}

func TestDecodeRawManifestFlags(t *testing.T) {
	cmd := decodeRawManifestCommand()

	require.NotNil(t, cmd)
	require.Equal(t, "raw", cmd.Name)
	require.Len(t, cmd.Flags, 4) // --file, --base64, --json, --api-version
}

func TestApiVersionToManifestVersion(t *testing.T) {
	v, err := apiVersionToManifestVersion("v1")
	require.NoError(t, err)
	require.Equal(t, manifest.V1, v)

	v, err = apiVersionToManifestVersion("v2")
	require.NoError(t, err)
	require.Equal(t, manifest.V2, v)

	_, err = apiVersionToManifestVersion("")
	require.Error(t, err)

	_, err = apiVersionToManifestVersion("v3")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported api-version")
}
