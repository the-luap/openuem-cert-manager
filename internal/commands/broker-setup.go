package commands

import (
	"fmt"

	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/openuem-cert-manager/internal/broker"
	"github.com/urfave/cli/v2"
)

func SetupIndividualBroker() *cli.Command {
	return &cli.Command{
		Name: "individual-broker", Usage: "Initialize private service NKeys and an isolated individual-agent broker configuration",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "directory", Usage: "Absolute directory for protected service seeds and broker.json", Required: true},
			&cli.StringFlag{Name: "name", Value: "openuem-individual", Usage: "Broker server name"},
			&cli.StringFlag{Name: "listen", Value: "127.0.0.1:4222", Usage: "Private native TLS listener IP and port"},
			&cli.StringFlag{Name: "websocket-listen", Value: "127.0.0.1:9222", Usage: "Private gateway WSS listener IP and port"},
			&cli.StringFlag{Name: "tls-cert", Usage: "Absolute broker TLS certificate path as seen by NATS", Required: true},
			&cli.StringFlag{Name: "tls-key", Usage: "Absolute broker TLS key path as seen by NATS", Required: true},
			&cli.StringFlag{Name: "gateway-ca", Usage: "Absolute CA bundle path for gateway client TLS authentication", Required: true},
			&cli.StringFlag{Name: "store-directory", Usage: "Absolute JetStream data directory as seen by NATS", Required: true},
		},
		Action: func(ctx *cli.Context) error {
			_, err := broker.Initialize(ctx.String("directory"), enrollment.BrokerConfiguration{Name: ctx.String("name"), Listen: ctx.String("listen"), WebsocketListen: ctx.String("websocket-listen"), CertificateFile: ctx.String("tls-cert"), KeyFile: ctx.String("tls-key"), GatewayCAFile: ctx.String("gateway-ca"), StoreDirectory: ctx.String("store-directory")})
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(ctx.App.Writer, "Individual broker configuration is ready. Service keys remain in protected files.")
			return err
		},
	}
}
