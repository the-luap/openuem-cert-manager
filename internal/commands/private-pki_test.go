//go:build linux || darwin

package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"
)

func TestPrivatePKICLIUsesExplicitPrivateDirectoryAndPreservesKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pki")
	var output bytes.Buffer
	run := func(args ...string) error {
		app := &cli.App{Commands: PlatformSetupCommands(), Writer: &output, ErrWriter: &output}
		return app.Run(append([]string{"cert-manager", "private-pki", "--directory", path}, args...))
	}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Private PKI is ready") || strings.Contains(output.String(), "PRIVATE KEY") {
		t.Fatal("CLI did not report a credential-free completion")
	}
	before, err := os.ReadFile(filepath.Join(path, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	if err := run(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(path, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if !bytes.Equal(before, after) {
		t.Fatal("CLI retry replaced private identities")
	}
	if err := run("--console-dns", "other.internal"); err == nil {
		t.Fatal("CLI accepted different backend names in retained state")
	}
}

func TestPrivatePKICLIDatabaseIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pki")
	var output bytes.Buffer
	run := func(names ...string) error {
		app := &cli.App{Commands: PlatformSetupCommands(), Writer: &output, ErrWriter: &output}
		args := []string{"cert-manager", "private-pki", "--directory", path}
		for _, name := range names {
			args = append(args, "--database-dns", name)
		}
		return app.Run(args)
	}
	if err := run("database.internal"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(path, "database/server.key"))
	if err != nil {
		t.Fatal("database CLI did not export its identity")
	}
	defer clear(before)
	if err := run("database.internal"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(path, "database/server.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if !bytes.Equal(before, after) || strings.Contains(output.String(), "PRIVATE KEY") {
		t.Fatal("CLI replaced or exposed a database key")
	}
	if err := run(); err == nil {
		t.Fatal("CLI accepted omission of committed database names")
	}
}

func TestPrivatePKICLIAdministratorAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pki")
	var output bytes.Buffer
	run := func(enabled bool) error {
		app := &cli.App{Commands: PlatformSetupCommands(), Writer: &output, ErrWriter: &output}
		args := []string{"cert-manager", "private-pki", "--directory", path}
		if enabled {
			args = append(args, "--administrator-authority")
		}
		return app.Run(args)
	}
	if err := run(true); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(path, "administrator-authority/ca.key"))
	if err != nil {
		t.Fatal("administrator CLI did not export its protected authority")
	}
	defer clear(before)
	if err := run(true); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(path, "administrator-authority/ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(after)
	if !bytes.Equal(before, after) || strings.Contains(output.String(), "PRIVATE KEY") {
		t.Fatal("CLI replaced or exposed an administrator authority key")
	}
	if err := run(false); err == nil {
		t.Fatal("CLI accepted omission of the committed administrator authority")
	}
}
