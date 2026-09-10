//go:build linux || darwin

package commands

import (
	"encoding/json"
	"os"
	"os/signal"
	"syscall"

	"github.com/open-uem/openuem-cert-manager/internal/broker"
	"github.com/urfave/cli/v2"
)

func SetupIndividualBrokerUpgrade() *cli.Command {
	return &cli.Command{
		Name: "individual-broker-upgrade", Usage: "Preview or apply the supported worker grant upgrade while retaining service identities and storage",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "directory", Required: true, Usage: "Existing private broker configuration and service seed directory"},
			&cli.BoolFlag{Name: "check", Usage: "Print public before/after hashes without changing any file"},
			&cli.StringFlag{Name: "expected-sha256", Usage: "Reviewed before_sha256 from --check; required when applying"},
		},
		Action: func(c *cli.Context) error {
			if c.NArg() != 0 || c.Bool("check") && c.IsSet("expected-sha256") {
				return broker.ErrUpgrade
			}
			ctx, stop := signal.NotifyContext(c.Context, os.Interrupt, syscall.SIGTERM)
			defer stop()
			var plan broker.UpgradePlan
			var err error
			if c.Bool("check") {
				plan, err = broker.PlanUpgrade(ctx, c.String("directory"))
			} else {
				plan, err = broker.Upgrade(ctx, c.String("directory"), c.String("expected-sha256"))
			}
			if err != nil {
				return err
			}
			if json.NewEncoder(c.App.Writer).Encode(plan) != nil {
				return broker.ErrUpgrade
			}
			return nil
		},
	}
}
