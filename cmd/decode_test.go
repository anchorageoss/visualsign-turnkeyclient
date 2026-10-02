package cmd

import (
	"bytes"
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
	"github.com/anchorageoss/visualsign-turnkeyclient/testdata"
	"github.com/stretchr/testify/require"
)

func TestDecodeCommand(t *testing.T) {
	cmd := DecodeCommand()

	require.NotNil(t, cmd)
	require.Equal(t, "decode-manifest", cmd.Name)
	require.Len(t, cmd.Commands, 1)
}

func TestDecodeManifestEnvelopeCommand(t *testing.T) {
	cmd := decodeManifestEnvelopeCommand()

	require.NotNil(t, cmd)
	require.Equal(t, "envelope", cmd.Name)

	// Check flags exist: --file, --base64, --json
	require.Len(t, cmd.Flags, 3)
}

// TestPrintManifestTextJSONProjection verifies that printManifestText, fed
// the ManifestJSONV2.ToManifest() projection, renders the JSON envelope's
// content correctly for the decode-manifest text-output path.
func TestPrintManifestTextJSONProjection(t *testing.T) {
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
	// as a raw numeric code.
	require.Contains(t, out, "Restart Policy: Always")
	require.Contains(t, out, `[0] "--pivot-flag"`)
	require.Contains(t, out, "type=server host=\"0.0.0.0\" port=3000")
	require.Contains(t, out, "DebugMode: false")

	// Manifest Set / Share Set thresholds and member counts
	require.Contains(t, out, "Manifest Set:\n  Threshold: 2\n  Members: 2\n")
	require.Contains(t, out, "Share Set:\n  Threshold: 1\n  Members: 1\n")
}
