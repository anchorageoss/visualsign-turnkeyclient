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

// apiVersionToManifestVersion maps the CLI --api-version flag to a ManifestVersion.
// Returns an error for unsupported values.
func apiVersionToManifestVersion(apiVersion string) (manifest.ManifestVersion, error) {
	switch apiVersion {
	case "v1":
		return manifest.V1, nil
	case "v2":
		return manifest.V2, nil
	default:
		return 0, fmt.Errorf("unsupported --api-version %q: must be \"v1\" or \"v2\"", apiVersion)
	}
}

// DecodeCommand creates the decode commands
func DecodeCommand() *cli.Command {
	return &cli.Command{
		Name:  "decode-manifest",
		Usage: "Decode QoS manifest",
		Commands: []*cli.Command{
			decodeRawManifestCommand(),
			decodeManifestEnvelopeCommand(),
		},
	}
}

func decodeRawManifestCommand() *cli.Command {
	return &cli.Command{
		Name:  "raw",
		Usage: "Decode raw manifest (no approvals)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "file",
				Usage: "Path to raw manifest binary file",
			},
			&cli.StringFlag{
				Name:  "base64",
				Usage: "Base64-encoded raw manifest",
			},
			&cli.BoolFlag{
				Name:  "json",
				Usage: "Output in JSON format",
			},
			&cli.StringFlag{
				Name:  "api-version",
				Usage: "Manifest format version (v1 or v2)",
				Value: "v2",
			},
		},
		Action: runDecodeRawManifestCommand,
	}
}

func runDecodeRawManifestCommand(ctx context.Context, cmd *cli.Command) error {
	filePath := cmd.String("file")
	b64 := cmd.String("base64")
	asJSON := cmd.Bool("json")

	if filePath == "" && b64 == "" {
		return fmt.Errorf("either --file or --base64 must be provided")
	}
	if filePath != "" && b64 != "" {
		return fmt.Errorf("only one of --file or --base64 should be provided")
	}

	mv, err := apiVersionToManifestVersion(cmd.String("api-version"))
	if err != nil {
		return err
	}

	var m *manifest.Manifest
	var manifestBytes []byte

	if filePath != "" {
		m, manifestBytes, err = manifest.DecodeRawManifestFromFile(filePath, mv)
	} else {
		m, manifestBytes, err = manifest.DecodeRawManifestFromBase64(b64, mv)
	}

	if err != nil {
		return fmt.Errorf("failed to decode raw manifest: %w", err)
	}

	manifestHash := manifest.ComputeHash(manifestBytes)

	if asJSON {
		// Format manifest for JSON output
		formatter := verify.NewFormatter()
		output := formatter.FormatManifestJSON(m)
		output["hash"] = manifestHash

		jsonBytes, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal output: %w", err)
		}
		fmt.Println(string(jsonBytes))
	} else {
		// Text output
		fmt.Printf("=== QoS Manifest ===\n")
		fmt.Printf("Manifest Hash: %s\n\n", manifestHash)

		formatter := verify.NewFormatter()
		fmt.Print(formatter.FormatManifest(m))
	}

	return nil
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
			&cli.StringFlag{
				Name:  "api-version",
				Usage: "Manifest format version (v1 or v2)",
				Value: "v2",
			},
		},
		Action: runDecodeManifestEnvelopeCommand,
	}
}

// printHashesAndApprovals writes the "Hashes" and "Approvals" sections shared
// by both the Borsh and JSON envelope text-output formats.
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

// printPCRs writes the "Enclave (Nitro Config)" section shared by both the
// Borsh and JSON envelope text-output formats.
func printPCRs(w io.Writer, pcr0, pcr1, pcr2, pcr3 []byte) {
	_, _ = fmt.Fprintf(w, "\nEnclave (Nitro Config):\n")
	_, _ = fmt.Fprintf(w, "  PCR0: %s\n", hex.EncodeToString(pcr0))
	_, _ = fmt.Fprintf(w, "  PCR1: %s\n", hex.EncodeToString(pcr1))
	_, _ = fmt.Fprintf(w, "  PCR2: %s\n", hex.EncodeToString(pcr2))
	_, _ = fmt.Fprintf(w, "  PCR3: %s\n", hex.EncodeToString(pcr3))
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

	mv, err := apiVersionToManifestVersion(cmd.String("api-version"))
	if err != nil {
		return err
	}

	var envelopeBytes []byte
	if filePath != "" {
		envelopeBytes, err = os.ReadFile(filePath)
	} else {
		envelopeBytes, err = base64.StdEncoding.DecodeString(b64)
	}
	if err != nil {
		return fmt.Errorf("failed to read manifest envelope: %w", err)
	}

	if manifest.DetectEnvelopeFormat(envelopeBytes) == manifest.EnvelopeFormatJSON {
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
			fmt.Fprintf(os.Stderr, "=== QoS JSON Manifest Decoded ===\n\n")
			fmt.Fprintf(os.Stderr, "Namespace:\n")
			fmt.Fprintf(os.Stderr, "  Name: %q\n", jsonEnv.Manifest.Namespace.Name)
			fmt.Fprintf(os.Stderr, "  Nonce: %d\n", jsonEnv.Manifest.Namespace.Nonce)
			fmt.Fprintf(os.Stderr, "  Quorum Key: %s\n", hex.EncodeToString(jsonEnv.Manifest.Namespace.QuorumKey))

			fmt.Fprintf(os.Stderr, "\nPivot Config:\n")
			fmt.Fprintf(os.Stderr, "  Binary Hash: %x\n", []byte(jsonEnv.Manifest.Pivot.Hash))
			fmt.Fprintf(os.Stderr, "  Restart Policy: %s\n", jsonEnv.Manifest.Pivot.Restart)
			printIndexedQuoted(os.Stderr, "    ", "  Args:\n", jsonEnv.Manifest.Pivot.Args)
			if len(jsonEnv.Manifest.Pivot.BridgeConfig) > 0 {
				fmt.Fprintf(os.Stderr, "  BridgeConfig:\n")
				for i, bc := range jsonEnv.Manifest.Pivot.BridgeConfig {
					host := ""
					if bc.Host != nil {
						host = *bc.Host
					}
					fmt.Fprintf(os.Stderr, "    [%d] type=%s host=%q port=%d\n", i, bc.Type, host, bc.Port)
				}
			}
			fmt.Fprintf(os.Stderr, "  DebugMode: %v\n", jsonEnv.Manifest.Pivot.DebugMode)
			if len(jsonEnv.Manifest.Pivot.Env) > 0 {
				fmt.Fprintf(os.Stderr, "  Env:\n")
				names := make([]string, 0, len(jsonEnv.Manifest.Pivot.Env))
				for name := range jsonEnv.Manifest.Pivot.Env {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					if value := jsonEnv.Manifest.Pivot.Env[name]; value.Plain != nil {
						fmt.Fprintf(os.Stderr, "    %q=%q\n", name, value.Plain.Value)
					}
				}
			}

			if jsonEnv.Manifest.Dns != nil {
				printIndexedQuoted(os.Stderr, "  ", "\nDNS Resolvers:\n", jsonEnv.Manifest.Dns.Resolvers)
			}

			fmt.Fprintf(os.Stderr, "\nManifest Set:\n")
			fmt.Fprintf(os.Stderr, "  Threshold: %d\n", jsonEnv.Manifest.ManifestSet.Threshold)
			fmt.Fprintf(os.Stderr, "  Members: %d\n", len(jsonEnv.Manifest.ManifestSet.Members))

			fmt.Fprintf(os.Stderr, "\nShare Set:\n")
			fmt.Fprintf(os.Stderr, "  Threshold: %d\n", jsonEnv.Manifest.ShareSet.Threshold)
			fmt.Fprintf(os.Stderr, "  Members: %d\n", len(jsonEnv.Manifest.ShareSet.Members))

			printPCRs(os.Stderr, jsonEnv.Manifest.Enclave.Pcr0, jsonEnv.Manifest.Enclave.Pcr1, jsonEnv.Manifest.Enclave.Pcr2, jsonEnv.Manifest.Enclave.Pcr3)

			printHashesAndApprovals(manifestHash, envelopeHash, len(jsonEnv.ManifestSetApprovals), len(jsonEnv.ShareSetApprovals))
		}
		return nil
	}

	envelope, _, manifestBytes, envelopeBytes, err := manifest.DecodeManifestEnvelopeFromBytes(envelopeBytes, mv)
	if err != nil {
		return fmt.Errorf("failed to decode manifest envelope: %w", err)
	}

	manifestHash := manifest.ComputeHash(manifestBytes)
	envelopeHash := manifest.ComputeHash(envelopeBytes)

	if asJSON {
		// Format envelope for JSON output
		formatter := verify.NewFormatter()
		output := formatter.FormatManifestEnvelopeJSON(envelope)
		output["manifestHash"] = manifestHash
		output["envelopeHash"] = envelopeHash

		jsonBytes, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonBytes))
	} else {
		// Human-readable output
		fmt.Fprintf(os.Stderr, "=== QoS Manifest Decoded ===\n\n")
		fmt.Fprintf(os.Stderr, "Namespace:\n")
		fmt.Fprintf(os.Stderr, "  Name: %s\n", envelope.Manifest.Namespace.Name)
		fmt.Fprintf(os.Stderr, "  Nonce: %d\n", envelope.Manifest.Namespace.Nonce)

		fmt.Fprintf(os.Stderr, "\nPivot Config:\n")
		fmt.Fprintf(os.Stderr, "  Binary Hash: %s\n", fmt.Sprintf("%x", envelope.Manifest.Pivot.Hash[:]))
		fmt.Fprintf(os.Stderr, "  Restart Policy: %d\n", envelope.Manifest.Pivot.Restart)

		fmt.Fprintf(os.Stderr, "\nManifest Set:\n")
		fmt.Fprintf(os.Stderr, "  Threshold: %d\n", envelope.Manifest.ManifestSet.Threshold)
		fmt.Fprintf(os.Stderr, "  Members: %d\n", len(envelope.Manifest.ManifestSet.Members))

		printPCRs(os.Stderr, envelope.Manifest.Enclave.Pcr0, envelope.Manifest.Enclave.Pcr1, envelope.Manifest.Enclave.Pcr2, envelope.Manifest.Enclave.Pcr3)

		printHashesAndApprovals(manifestHash, envelopeHash, len(envelope.ManifestSetApprovals), len(envelope.ShareSetApprovals))
	}

	return nil
}
