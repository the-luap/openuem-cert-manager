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
