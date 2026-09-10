package cmd

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
	"github.com/anchorageoss/visualsign-turnkeyclient/testdata"
	"github.com/near/borsh-go"
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
	// as a raw numeric code, for both text-output paths.
	require.Contains(t, out, "Restart Policy: Always")
	require.Contains(t, out, `[0] "--pivot-flag"`)
	require.Contains(t, out, "type=server host=\"0.0.0.0\" port=3000")
	require.Contains(t, out, "DebugMode: false")

	// Manifest Set / Share Set thresholds and member counts
	require.Contains(t, out, "Manifest Set:\n  Threshold: 2\n  Members: 2\n")
	require.Contains(t, out, "Share Set:\n  Threshold: 1\n  Members: 1\n")
}

// TestPrintManifestTextBorshWireRoundTrip verifies printManifestText against
// a Manifest that actually came off the Borsh wire (borsh.Serialize followed
// by manifest.DecodeRawManifestFromBase64, the same path the CLI's Borsh
// envelope branch uses), independently declared from
// TestPrintManifestTextJSONProjection's JSON fixture rather than copied out
// of it. This also exercises the BridgeConfig "client" variant
// (Enum/Client), which that JSON fixture never sends and which the earlier
// version of this test never covered.
func TestPrintManifestTextBorshWireRoundTrip(t *testing.T) {
	want := manifest.Manifest{
		Namespace: manifest.Namespace{
			Name:      "wire-round-trip-namespace",
			Nonce:     11,
			QuorumKey: []byte{0x04, 0x11, 0x22},
		},
		Pivot: manifest.PivotConfig{
			Hash:    manifest.Hash256{0xaa, 0xbb},
			Restart: manifest.RestartPolicyAlways,
			BridgeConfig: []manifest.BridgeConfig{
				{Enum: 0, Server: manifest.BridgeConfigServer{Port: 3000, Host: "0.0.0.0"}},
				{Enum: 1, Client: manifest.BridgeConfigClient{Port: 4000, Host: "upstream.internal"}},
			},
			DebugMode: true,
			Args:      []string{"--wire-flag"},
		},
		ManifestSet: manifest.ManifestSet{
			Threshold: 2,
			Members:   []manifest.QuorumMember{{Alias: "alpha", PubKey: []byte{0x01}}},
		},
		ShareSet: manifest.ShareSet{
			Threshold: 1,
			Members:   []manifest.QuorumMember{{Alias: "beta", PubKey: []byte{0x02}}},
		},
		Enclave: manifest.NitroConfig{
			Pcr0: bytes.Repeat([]byte{0x00}, 48),
			Pcr1: bytes.Repeat([]byte{0x01}, 48),
			Pcr2: bytes.Repeat([]byte{0x02}, 48),
			Pcr3: bytes.Repeat([]byte{0x03}, 48),
		},
	}

	manifestBytes, err := borsh.Serialize(want)
	require.NoError(t, err)

	decoded, _, err := manifest.DecodeRawManifestFromBase64(base64.StdEncoding.EncodeToString(manifestBytes), manifest.V2)
	require.NoError(t, err)

	var buf bytes.Buffer
	printManifestText(&buf, *decoded)
	out := buf.String()

	require.Contains(t, out, `Name: "wire-round-trip-namespace"`)
	require.Contains(t, out, "Nonce: 11")
	require.Contains(t, out, "Quorum Key: 041122")
	require.Contains(t, out, "Restart Policy: Always")
	require.Contains(t, out, `[0] "--wire-flag"`)
	require.Contains(t, out, `type=server host="0.0.0.0" port=3000`)
	require.Contains(t, out, `type=client host="upstream.internal" port=4000`)
	require.Contains(t, out, "DebugMode: true")
	require.Contains(t, out, "Manifest Set:\n  Threshold: 2\n  Members: 1\n")
	require.Contains(t, out, "Share Set:\n  Threshold: 1\n  Members: 1\n")
}
