package main

import (
	"log"
	"os"

	"github.com/open-uem/openuem-cert-manager/internal/commands"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:      "openuem-cert-manager",
		Commands:  getCommands(),
		Usage:     "Generate CA and server certificates required by OpenUEM",
		Authors:   []*cli.Author{{Name: "Miguel Angel Alvarez Cabrerizo", Email: "mcabrerizo@openuem.eu"}},
		Copyright: "2025 - Miguel Angel Alvarez Cabrerizo <https://github.com/doncicuto>",
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

// TODO Generate TOML, INI or similar file to store organizations information

func getCommands() []*cli.Command {
	return append([]*cli.Command{
		commands.SetupIndividualBroker(),
		commands.CreateClientCertificate(),
		commands.CreateUserCertificate(),
		commands.CreateCA(),
		commands.RevokeCertificate(),
		commands.CreateServerCertificate(),
		commands.GetCertificateSerial(),
		commands.CreateCodeSigningCertificate(),
	}, commands.PlatformSetupCommands()...)
}
