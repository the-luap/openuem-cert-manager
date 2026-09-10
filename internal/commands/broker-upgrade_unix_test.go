//go:build linux || darwin

package commands

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-uem/openuem-cert-manager/internal/broker"
	"github.com/urfave/cli/v2"
)

func TestIndividualBrokerUpgradeCLI(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "broker")
	var output bytes.Buffer
	run := func(arguments ...string) error {
		output.Reset()
		app := &cli.App{Commands: append([]*cli.Command{SetupIndividualBroker()}, PlatformSetupCommands()...), Writer: &output, ErrWriter: &output}
		return app.Run(append([]string{"cert-manager"}, arguments...))
	}
	if err := run("individual-broker", "--directory", directory, "--tls-cert", filepath.Join(directory, "server.pem"), "--tls-key", filepath.Join(directory, "server.key"), "--gateway-ca", filepath.Join(directory, "ca.pem"), "--store-directory", filepath.Join(directory, "jetstream")); err != nil {
		t.Fatal(err)
	}
	if err := run("individual-broker-upgrade", "--directory", directory, "--check"); err != nil {
		t.Fatal(err)
	}
	var plan broker.UpgradePlan
	if json.Unmarshal(output.Bytes(), &plan) != nil || plan.ChangeRequired {
		t.Fatal("current configuration was not recognized")
	}
	data, _ := os.ReadFile(filepath.Join(directory, "broker.json"))
	hash := sha256.Sum256(data)
	if plan.Before != hex.EncodeToString(hash[:]) || plan.Before != plan.After {
		t.Fatal("preview hashes do not match configuration")
	}
	if _, err := os.Lstat(filepath.Join(directory, "broker-upgrade.lock")); !os.IsNotExist(err) {
		t.Fatal("preview created a lease")
	}
	if err := run("individual-broker-upgrade", "--directory", directory, "--expected-sha256", plan.Before); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"authorization-issuer.seed", "authorization-user.seed", "revocation-user.seed", "worker-user.seed", "console-user.seed", "provisioner-user.seed"} {
		value, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(output.Bytes(), value) {
			t.Fatal("CLI exposed a service seed")
		}
		clear(value)
	}
	for _, arguments := range [][]string{
		{"individual-broker-upgrade", "--directory", directory},
		{"individual-broker-upgrade", "--directory", directory, "--expected-sha256", "synthetic-secret"},
		{"individual-broker-upgrade", "--directory", directory, "--check", "--expected-sha256", plan.Before},
		{"individual-broker-upgrade", "--directory", directory, "--check", "synthetic-secret"},
	} {
		err := run(arguments...)
		if err == nil || strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(output.String(), "synthetic-secret") {
			t.Fatal("invalid upgrade arguments accepted or echoed")
		}
	}
}
