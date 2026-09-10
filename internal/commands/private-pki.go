//go:build linux || darwin

package commands

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/open-uem/openuem-cert-manager/internal/privatepki"
	"github.com/urfave/cli/v2"
)

func PlatformSetupCommands() []*cli.Command {
	return []*cli.Command{{
		Name: "private-pki", Usage: "Initialize and verify private backend and gateway TLS identities without replacing existing keys",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "directory", Required: true, Usage: "New or matching private initialization directory under an existing trusted parent"},
			&cli.StringFlag{Name: "name", Value: "openuem", Usage: "Stable installation name"},
			&cli.StringSliceFlag{Name: "console-dns", Value: cli.NewStringSlice("console.internal"), Usage: "Private DNS names used for console, login and MDM backends"},
			&cli.StringSliceFlag{Name: "broker-dns", Value: cli.NewStringSlice("nats.internal"), Usage: "Private DNS names used for the individual-agent broker"},
		},
		Action: func(ctx *cli.Context) error {
			request, stop := signal.NotifyContext(ctx.Context, os.Interrupt, syscall.SIGTERM)
			defer stop()
			_, err := privatepki.Initialize(request, ctx.String("directory"), privatepki.Config{Version: 1, Name: ctx.String("name"), ConsoleNames: ctx.StringSlice("console-dns"), BrokerNames: ctx.StringSlice("broker-dns")})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(ctx.App.Writer, "Private PKI is ready. Mount only each service's own directory; keep authority keys offline.")
			return err
		},
	}}
}
