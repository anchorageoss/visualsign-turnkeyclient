package cmd

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
	"github.com/anchorageoss/visualsign-turnkeyclient/verify"
	"github.com/urfave/cli/v3"
)

// DecodeCommand creates the decode commands
func DecodeCommand() *cli.Command {
	return &cli.Command{
		Name:  "decode-manifest",
		Usage: "Decode QoS manifest",
		Commands: []*cli.Command{
			decodeManifestEnvelopeCommand(),
		},
	}
}

func decodeManifestEnvelopeCommand() *cli.Command {
	return &cli.Command{
		Name:  "envelope",
		Usage: "Decode manifest envelope (with approvals)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "file",
				Usage: "Path to manifest envelope binary file",
			},
			&cli.StringFlag{
				Name:  "base64",
				Usage: "Base64-encoded manifest envelope",
			},
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Output in JSON format",
			},
		},
		Action: runDecodeManifestEnvelopeCommand,
	}
}

// printHashesAndApprovals writes the "Hashes" and "Approvals" sections of the
// envelope text-output format.
func printHashesAndApprovals(manifestHash, envelopeHash string, manifestSetApprovals, shareSetApprovals int) {
	fmt.Fprintf(os.Stderr, "\nHashes:\n")
	fmt.Fprintf(os.Stderr, "  Manifest: %s\n", manifestHash)
	fmt.Fprintf(os.Stderr, "  Envelope: %s\n", envelopeHash)

	fmt.Fprintf(os.Stderr, "\nApprovals:\n")
	fmt.Fprintf(os.Stderr, "  Manifest Set Approvals: %d\n", manifestSetApprovals)
	fmt.Fprintf(os.Stderr, "  Share Set Approvals: %d\n", shareSetApprovals)
}

// printIndexedQuoted writes header, then one "<indent>[i] %q" line per item.
func printIndexedQuoted(w io.Writer, indent, header string, items []string) {
	_, _ = fmt.Fprint(w, header)
	for i, item := range items {
		_, _ = fmt.Fprintf(w, "%s[%d] %q\n", indent, i, item)
	}
}

// printPCRs writes the "Enclave (Nitro Config)" section of the envelope
// text-output format.
func printPCRs(w io.Writer, pcr0, pcr1, pcr2, pcr3 []byte) {
	_, _ = fmt.Fprintf(w, "\nEnclave (Nitro Config):\n")
	_, _ = fmt.Fprintf(w, "  PCR0: %s\n", hex.EncodeToString(pcr0))
	_, _ = fmt.Fprintf(w, "  PCR1: %s\n", hex.EncodeToString(pcr1))
	_, _ = fmt.Fprintf(w, "  PCR2: %s\n", hex.EncodeToString(pcr2))
	_, _ = fmt.Fprintf(w, "  PCR3: %s\n", hex.EncodeToString(pcr3))
}

// printQuorumSet writes a "Threshold"/"Members" summary shared by the
// Manifest Set and Share Set sections of both text-output formats.
func printQuorumSet(w io.Writer, label string, threshold uint32, memberCount int) {
	_, _ = fmt.Fprintf(w, "\n%s:\n", label)
	_, _ = fmt.Fprintf(w, "  Threshold: %d\n", threshold)
	_, _ = fmt.Fprintf(w, "  Members: %d\n", memberCount)
}

// printManifestText writes the Namespace, Pivot Config, Manifest Set and
// Share Set sections. The caller prints JSON-only sections (Dns, Pivot.Env).
func printManifestText(w io.Writer, m manifest.Manifest) {
	_, _ = fmt.Fprintf(w, "Namespace:\n")
	_, _ = fmt.Fprintf(w, "  Name: %q\n", m.Namespace.Name)
	_, _ = fmt.Fprintf(w, "  Nonce: %d\n", m.Namespace.Nonce)
	_, _ = fmt.Fprintf(w, "  Quorum Key: %s\n", hex.EncodeToString(m.Namespace.QuorumKey))

	_, _ = fmt.Fprintf(w, "\nPivot Config:\n")
	_, _ = fmt.Fprintf(w, "  Binary Hash: %s\n", hex.EncodeToString(m.Pivot.Hash[:]))
	_, _ = fmt.Fprintf(w, "  Restart Policy: %s\n", m.Pivot.Restart)
	printIndexedQuoted(w, "    ", "  Args:\n", m.Pivot.Args)
	if len(m.Pivot.BridgeConfig) > 0 {
		_, _ = fmt.Fprintf(w, "  BridgeConfig:\n")
		for i, bc := range m.Pivot.BridgeConfig {
			var bridgeType, host string
			var port uint16
			switch bc.Enum {
			case 0:
				bridgeType, host, port = manifest.BridgeConfigTypeServer, bc.Server.Host, bc.Server.Port
			case 1:
				bridgeType, host, port = manifest.BridgeConfigTypeClient, bc.Client.Host, bc.Client.Port
			}
			_, _ = fmt.Fprintf(w, "    [%d] type=%s host=%q port=%d\n", i, bridgeType, host, port)
		}
	}
	_, _ = fmt.Fprintf(w, "  DebugMode: %v\n", m.Pivot.DebugMode)

	printQuorumSet(w, "Manifest Set", m.ManifestSet.Threshold, len(m.ManifestSet.Members))
	printQuorumSet(w, "Share Set", m.ShareSet.Threshold, len(m.ShareSet.Members))
}

func runDecodeManifestEnvelopeCommand(ctx context.Context, cmd *cli.Command) error {
	filePath := cmd.String("file")
	b64 := cmd.String("base64")
	asJSON := cmd.Bool("json")

	if filePath == "" && b64 == "" {
		return fmt.Errorf("either --file or --base64 must be provided")
	}
	if filePath != "" && b64 != "" {
		return fmt.Errorf("only one of --file or --base64 should be provided")
	}

	var envelopeBytes []byte
	var err error
	if filePath != "" {
		envelopeBytes, err = os.ReadFile(filePath)
	} else {
		envelopeBytes, err = base64.StdEncoding.DecodeString(b64)
	}
	if err != nil {
		return fmt.Errorf("failed to read manifest envelope: %w", err)
	}

	jsonEnv, manifestBytes, jsonErr := manifest.DecodeJSONManifestEnvelope(envelopeBytes)
	if jsonErr != nil {
		return fmt.Errorf("failed to decode QOS JSON manifest envelope: %w", jsonErr)
	}

	manifestHash := manifest.ComputeHash(manifestBytes)
	envelopeHash := manifest.ComputeHash(envelopeBytes)

	formatter := verify.NewFormatter()
	if asJSON {
		output := formatter.FormatManifestEnvelopeJSONV2(jsonEnv)
		output["manifestHash"] = manifestHash
		output["envelopeHash"] = envelopeHash

		jsonBytes, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonBytes))
	} else {
		env := jsonEnv.ToManifestEnvelope()

		fmt.Fprintf(os.Stderr, "=== QoS JSON Manifest Decoded ===\n\n")
		printManifestText(os.Stderr, env.Manifest)

		// Dns and Pivot.Env are not on manifest.Manifest; print from the JSON envelope.
		if len(jsonEnv.Manifest.Pivot.Env) > 0 {
			fmt.Fprintf(os.Stderr, "\nEnv:\n")
			names := make([]string, 0, len(jsonEnv.Manifest.Pivot.Env))
			for name := range jsonEnv.Manifest.Pivot.Env {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				if value := jsonEnv.Manifest.Pivot.Env[name]; value.Plain != nil {
					fmt.Fprintf(os.Stderr, "  %q=%q\n", name, value.Plain.Value)
				}
			}
		}
		if jsonEnv.Manifest.Dns != nil {
			printIndexedQuoted(os.Stderr, "  ", "\nDNS Resolvers:\n", jsonEnv.Manifest.Dns.Resolvers)
		}

		printPCRs(os.Stderr, env.Manifest.Enclave.Pcr0, env.Manifest.Enclave.Pcr1, env.Manifest.Enclave.Pcr2, env.Manifest.Enclave.Pcr3)

		printHashesAndApprovals(manifestHash, envelopeHash, len(jsonEnv.ManifestSetApprovals), len(jsonEnv.ShareSetApprovals))
	}

	return nil
}
