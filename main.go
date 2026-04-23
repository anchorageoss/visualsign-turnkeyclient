package main

import (
	"context"
	"log"
	"os"

	"github.com/anchorageoss/visualsign-turnkeyclient/cmd"
	"github.com/anchorageoss/visualsign-turnkeyclient/version"
	"github.com/urfave/cli/v3"
)

func main() {
	app := &cli.Command{
		Name:    "turnkey-client",
		Usage:   "Turnkey Visualsign Client",
		Version: version.String(),
		Commands: []*cli.Command{
			cmd.ParseCommand(),
			cmd.VerifyCommand(),
			cmd.DecodeCommand(),
			cmd.AttestationCommand(),
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
