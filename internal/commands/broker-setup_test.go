package commands

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/urfave/cli/v2"
)

func TestIndividualBrokerCLIProducesProtectedFilesWithoutPrintingSeeds(t *testing.T) {
	directory := t.TempDir()
	var output bytes.Buffer
	app := &cli.App{Commands: []*cli.Command{SetupIndividualBroker()}, Writer: &output, ErrWriter: &output}
	args := []string{"cert-manager", "individual-broker", "--directory", directory,
		"--tls-cert", filepath.Join(directory, "broker.pem"), "--tls-key", filepath.Join(directory, "broker.key"),
		"--gateway-ca", filepath.Join(directory, "gateway-ca.pem"), "--store-directory", filepath.Join(directory, "jetstream")}
	if err := app.Run(args); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Individual broker configuration is ready") {
		t.Fatal("CLI did not explain its result")
	}
	for _, name := range []string{"authorization-issuer.seed", "authorization-user.seed", "revocation-user.seed", "worker-user.seed", "console-user.seed", "provisioner-user.seed"} {
		seed, err := keyfile.Read(filepath.Join(directory, name), 512)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(output.Bytes(), seed) {
			t.Fatal("CLI printed a private service seed")
		}
		clear(seed)
	}
	if _, err := keyfile.Read(filepath.Join(directory, "broker.json"), 64<<10); err != nil {
		t.Fatal(err)
	}
}
