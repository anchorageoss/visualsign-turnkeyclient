package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/anchorageoss/visualsign-turnkeyclient/api"
	"github.com/anchorageoss/visualsign-turnkeyclient/keys"
	"github.com/urfave/cli/v3"
)

// ParseCommand creates the parse command
func ParseCommand() *cli.Command {
	return &cli.Command{
		Name:  "parse",
		Usage: "Parse transaction and extract attestations",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "host",
				Usage:    "Turnkey API host URL",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "organization-id",
				Usage:    "Organization ID",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "key-name",
				Usage:    "API key name",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "unsigned-payload",
				Usage:    "Unsigned transaction payload (base64)",
				Required: true,
			},
		},
		Action: runParseCommand,
	}
}

func runParseCommand(ctx context.Context, cmd *cli.Command) error {
	// Extract flags
	hostURI := cmd.String("host")
	organizationID := cmd.String("organization-id")
	keyName := cmd.String("key-name")
	unsignedPayload := cmd.String("unsigned-payload")

	// Create API client
	httpClient := &http.Client{}
	keyProvider := &keys.FileKeyProvider{KeyName: keyName}
	apiClient, err := api.NewClient(hostURI, httpClient, organizationID, keyProvider)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}

	// Call API to get signable payload
	response, err := apiClient.CreateSignablePayload(ctx, &api.CreateSignablePayloadRequest{
		UnsignedPayload: unsignedPayload,
		Chain:           "CHAIN_SOLANA",
	})
	if err != nil {
		return fmt.Errorf("failed to create signable payload: %w", err)
	}

	// Output the result as JSON to stdout
	output, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	fmt.Println(string(output))

	// Provide summary information to stderr
	fmt.Fprintf(os.Stderr, "\n=== TURNKEY CLIENT SUMMARY ===\n")
	fmt.Fprintf(os.Stderr, "✓ Transaction parsed successfully\n")
	fmt.Fprintf(os.Stderr, "✓ Signable payload extracted (%d characters)\n", len(response.SignablePayload))
	if len(response.Attestations) > 0 {
		fmt.Fprintf(os.Stderr, "✓ Attestations extracted:\n")
		for attestationType := range response.Attestations {
			fmt.Fprintf(os.Stderr, "  - %s\n", attestationType)
		}
	} else {
		fmt.Fprintf(os.Stderr, "⚠ No attestations available\n")
	}
	if response.EphemeralPublicKeyHex != "" {
		fmt.Fprintf(os.Stderr, "✓ Boot proof metadata:\n")
		fmt.Fprintf(os.Stderr, "  - ephemeralPublicKeyHex: %s\n", response.EphemeralPublicKeyHex)
		fmt.Fprintf(os.Stderr, "  - enclaveApp: %s\n", response.EnclaveApp)
		fmt.Fprintf(os.Stderr, "  - deploymentLabel: %s\n", response.DeploymentLabel)
	}

	return nil
}
