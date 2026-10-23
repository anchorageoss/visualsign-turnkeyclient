package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	nitroverifier "github.com/anchorageoss/awsnitroverifier"
	"github.com/anchorageoss/visualsign-turnkeyclient/api"
	"github.com/anchorageoss/visualsign-turnkeyclient/verify"
	"github.com/urfave/cli/v3"
)

// maxResponseFileBytes bounds how much of a saved response is read. Responses
// carry an attestation document and two manifests (tens of KB); this leaves
// room for an intermediate-output blob without letting a stray file or pipe
// exhaust memory.
const maxResponseFileBytes = 32 << 20

// VerifyResponseCommand verifies a VisualSign response that was already
// obtained, without calling any API: no host, organization or API key is
// needed. The checks are the ones `verify` runs after its API call.
func VerifyResponseCommand() *cli.Command {
	return &cli.Command{
		Name:  "verify-response",
		Usage: "Verify a saved VisualSign response offline (no API call, no API key)",
		Description: "Runs the same attestation, manifest, digest and signature checks as `verify` on a response body " +
			"captured earlier (for example from a backend that cannot be reached with a Turnkey stamp). " +
			"The request inputs (--unsigned-payload, --chain-metadata) must be the ones the response was produced for.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "response-file",
				Usage:    "File holding the raw JSON response body, or - for stdin",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "unsigned-payload",
				Usage:    "Unsigned transaction payload the response was produced for (base64 or hex)",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "chain-metadata",
				Usage: `Chain metadata JSON the request carried, if any (e.g. {"ethereum":{"abiMappings":{"0xAddr":{"value":"[...]"}}}})`,
			},
			&cli.StringFlag{
				Name:  "qos-manifest-hex",
				Usage: "Expected QoS manifest hash (hex format) to verify against UserData",
			},
			&cli.StringFlag{
				Name:  "pivot-binary-hash-hex",
				Usage: "Alternative name for QoS manifest hash (both verify against UserData)",
			},
			&cli.StringFlag{
				Name:  "save-qos-manifest",
				Usage: "Save the QoS manifest envelope to a binary file at the specified path",
			},
			&cli.StringFlag{
				Name:  "pcrs",
				Usage: "Expected PCR values in format: 0:<hex>,1:<hex>,... (e.g., 0:abc123,1:def456)",
			},
			&cli.BoolFlag{
				Name:  "debug",
				Usage: "Enable debug output (attestation document, PCR values, manifest details)",
			},
		},
		Action: runVerifyResponseCommand,
	}
}

// readResponseFile reads a response body from path, or from stdin when path is
// "-", refusing anything over maxResponseFileBytes.
func readResponseFile(path string, stdin io.Reader) ([]byte, error) {
	var r io.Reader = stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open response file: %w", err)
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxResponseFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	if len(data) > maxResponseFileBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxResponseFileBytes)
	}
	return data, nil
}

func runVerifyResponseCommand(ctx context.Context, cmd *cli.Command) error {
	pcrRules, err := ParsePCRs(cmd.String("pcrs"))
	if err != nil {
		return fmt.Errorf("failed to parse PCR specification: %w", err)
	}

	// VerifyResponse compares the input payload digest only when both the
	// payload and the response's digest are present. This command promises the
	// response is bound to --unsigned-payload, so require both.
	unsignedPayload := cmd.String("unsigned-payload")
	if unsignedPayload == "" {
		return errors.New("--unsigned-payload must not be empty")
	}

	body, err := readResponseFile(cmd.String("response-file"), os.Stdin)
	if err != nil {
		return err
	}
	response, err := api.ParseSignablePayloadResponse(body)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if response.InputPayloadDigest == "" {
		return errors.New("response has no inputPayloadDigest, so it cannot be bound to --unsigned-payload")
	}

	var chainMetadata *api.RequestChainMetadata
	if raw := cmd.String("chain-metadata"); raw != "" {
		chainMetadata = &api.RequestChainMetadata{}
		if err := json.Unmarshal([]byte(raw), chainMetadata); err != nil {
			return fmt.Errorf("invalid --chain-metadata JSON: %w", err)
		}
	}

	verifier := nitroverifier.NewVerifier(nitroverifier.AWSNitroVerifierOptions{
		SkipTimestampCheck: true,
		PCRRules:           pcrRules,
	})
	service := verify.NewService(nil, verifier)

	result, err := service.VerifyResponse(ctx, response, &verify.VerifyResponseRequest{
		UnsignedPayload:    unsignedPayload,
		QosManifestHex:     cmd.String("qos-manifest-hex"),
		PivotBinaryHashHex: cmd.String("pivot-binary-hash-hex"),
		SaveManifestPath:   cmd.String("save-qos-manifest"),
		ChainMetadata:      chainMetadata,
	})
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	return printVerifyResult(result, cmd.Bool("debug"))
}
