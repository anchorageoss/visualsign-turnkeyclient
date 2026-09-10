package cmd

import (
	"bytes"
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
	"github.com/anchorageoss/visualsign-turnkeyclient/testdata"
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
	require.Contains(t, err.Error(), "unsupported --api-version")

	_, err = apiVersionToManifestVersion("jsonv2")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported --api-version")
}

// TestPrintManifestTextBorshVsJSON verifies that printManifestText, now
// shared between the Borsh and JSON envelope text-output paths in
// runDecodeManifestEnvelopeCommand, renders the same sections and content
// for a native Borsh Manifest and for a JSON v2 manifest projected via
// ManifestJSONV2.ToManifest() — the behavior the two hand-duplicated
// formatting blocks previously had to keep in sync by hand.
func TestPrintManifestTextBorshVsJSON(t *testing.T) {
	jsonEnv, _, err := manifest.DecodeJSONManifestEnvelope(testdata.QosManifestEnvelopeV2JSON)
	require.NoError(t, err)

	env := jsonEnv.ToManifestEnvelope()

	var buf bytes.Buffer
	printManifestText(&buf, env.Manifest)
	out := buf.String()

	// Namespace
	require.Contains(t, out, `Name: "synthetic-turnkey-namespace"`)
	require.Contains(t, out, "Nonce: 7")
	require.Contains(t, out, "Quorum Key: 023333333333333333333333333333333333333333333333333333333333333333")

	// Pivot Config: restart policy renders via RestartPolicy.String(), not
	// as a raw numeric code, for both text-output paths.
	require.Contains(t, out, "Restart Policy: Always")
	require.Contains(t, out, `[0] "--pivot-flag"`)
	require.Contains(t, out, "type=server host=\"0.0.0.0\" port=3000")
	require.Contains(t, out, "DebugMode: false")

	// Manifest Set / Share Set thresholds and member counts
	require.Contains(t, out, "Manifest Set:\n  Threshold: 2\n  Members: 2\n")
	require.Contains(t, out, "Share Set:\n  Threshold: 1\n  Members: 1\n")

	// A hand-built Borsh manifest with the same values must render
	// identically through the shared formatter.
	borshManifest := manifest.Manifest{
		Namespace: env.Manifest.Namespace,
		Pivot:     env.Manifest.Pivot,
		ManifestSet: manifest.ManifestSet{
			Threshold: env.Manifest.ManifestSet.Threshold,
			Members:   env.Manifest.ManifestSet.Members,
		},
		ShareSet: manifest.ShareSet{
			Threshold: env.Manifest.ShareSet.Threshold,
			Members:   env.Manifest.ShareSet.Members,
		},
		Enclave: env.Manifest.Enclave,
	}
	var borshBuf bytes.Buffer
	printManifestText(&borshBuf, borshManifest)
	require.Equal(t, out, borshBuf.String())
}
