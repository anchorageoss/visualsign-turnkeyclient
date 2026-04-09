package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/anchorageoss/visualsign-turnkeyclient/manifest"
	"github.com/anchorageoss/visualsign-turnkeyclient/verify"
	"github.com/urfave/cli/v3"
)

// apiVersionToManifestVersion maps the CLI --api-version flag to a ManifestVersion.
func apiVersionToManifestVersion(apiVersion string) manifest.ManifestVersion {
	if apiVersion == "v1" {
		return manifest.V0
	}
	return manifest.V2
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

	mv := apiVersionToManifestVersion(cmd.String("api-version"))

	var m *manifest.Manifest
	var manifestBytes []byte
	var err error

	if filePath != "" {
		m, manifestBytes, err = manifest.DecodeRawManifestFromFile(filePath, mv)
	} else {
		m, manifestBytes, err = manifest.DecodeRawManifestFromBase64(b64, mv)
	}

	if err != nil {
		return fmt.Errorf("failed to decode raw manifest: %w", err)
	}

	// Compute manifest hash
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

	mv := apiVersionToManifestVersion(cmd.String("api-version"))

	var envelope *manifest.ManifestEnvelope
	var manifestBytes, envelopeBytes []byte
	var err error

	if filePath != "" {
		envelope, _, manifestBytes, envelopeBytes, err = manifest.DecodeManifestEnvelopeFromFile(filePath, mv)
	} else {
		envelope, _, manifestBytes, envelopeBytes, err = manifest.DecodeManifestEnvelopeFromBase64(b64, mv)
	}

	if err != nil {
		return fmt.Errorf("failed to decode manifest envelope: %w", err)
	}

	// Compute hashes
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

		fmt.Fprintf(os.Stderr, "\nEnclave (Nitro Config):\n")
		fmt.Fprintf(os.Stderr, "  PCR0: %s\n", fmt.Sprintf("%x", envelope.Manifest.Enclave.Pcr0))
		fmt.Fprintf(os.Stderr, "  PCR1: %s\n", fmt.Sprintf("%x", envelope.Manifest.Enclave.Pcr1))
		fmt.Fprintf(os.Stderr, "  PCR2: %s\n", fmt.Sprintf("%x", envelope.Manifest.Enclave.Pcr2))
		fmt.Fprintf(os.Stderr, "  PCR3: %s\n", fmt.Sprintf("%x", envelope.Manifest.Enclave.Pcr3))

		fmt.Fprintf(os.Stderr, "\nHashes:\n")
		fmt.Fprintf(os.Stderr, "  Manifest: %s\n", manifestHash)
		fmt.Fprintf(os.Stderr, "  Envelope: %s\n", envelopeHash)

		fmt.Fprintf(os.Stderr, "\nApprovals:\n")
		fmt.Fprintf(os.Stderr, "  Manifest Set Approvals: %d\n", len(envelope.ManifestSetApprovals))
		fmt.Fprintf(os.Stderr, "  Share Set Approvals: %d\n", len(envelope.ShareSetApprovals))
	}

	return nil
}
