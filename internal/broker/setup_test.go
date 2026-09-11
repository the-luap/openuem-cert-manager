package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/keyfile"
)

func TestSetupIncludesCurrentWorkerSubjects(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "broker")
	path, err := Initialize(directory, setupConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := keyfile.Read(filepath.Join(directory, "worker-user.seed"), 512)
	if err != nil {
		t.Fatal("worker identity is unavailable")
	}
	defer clear(seed)
	key, err := nkeys.FromSeed(seed)
	if err != nil {
		t.Fatal("worker identity is invalid")
	}
	defer key.Wipe()
	public, _ := key.PublicKey()
	var configuration struct {
		Accounts map[string]struct {
			Users []struct {
				Nkey        string
				Permissions struct{ Subscribe []string }
			}
		}
	}
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &configuration) != nil {
		t.Fatal("generated broker configuration is unreadable")
	}
	wanted := []string{"report", "hardware", "recovery", "rotation", "software", "deployresult", "agentconfig",
		"wingetcfg.profiles", "ansiblecfg.profiles", "wingetcfg.deploy", "wingetcfg.exclude", "wingetcfg.report"}
	for i := range wanted {
		wanted[i] = "uem.v1.agent.*.request." + wanted[i]
	}
	slices.Sort(wanted)
	found := 0
	for _, user := range configuration.Accounts["UEM_DEVICES"].Users {
		if user.Nkey == public {
			found++
			slices.Sort(user.Permissions.Subscribe)
			if !slices.Equal(user.Permissions.Subscribe, wanted) {
				t.Fatal("generated worker subscriptions omit or broaden the current RPC contract")
			}
		}
	}
	if found != 1 {
		t.Fatal("generated broker configuration has an ambiguous worker identity")
	}
}

func setupConfig(t *testing.T) enrollment.BrokerConfiguration {
	t.Helper()
	directory := t.TempDir()
	return enrollment.BrokerConfiguration{Name: "test-broker", Listen: "127.0.0.1:4222", WebsocketListen: "127.0.0.1:9222", CertificateFile: filepath.Join(directory, "broker.pem"), KeyFile: filepath.Join(directory, "broker.key"), GatewayCAFile: filepath.Join(directory, "gateway-ca.pem"), StoreDirectory: filepath.Join(directory, "jetstream")}
}

func TestSetupResumesPartialKeysAndDoesNotChangeInstalledIdentity(t *testing.T) {
	config := setupConfig(t)
	directory := filepath.Join(t.TempDir(), "credentials")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	issuer, _ := nkeys.CreateAccount()
	defer issuer.Wipe()
	seed, _ := issuer.Seed()
	defer clear(seed)
	if err := keyfile.Create(filepath.Join(directory, "authorization-issuer.seed"), seed); err != nil {
		t.Fatal(err)
	}
	path, err := Initialize(directory, config)
	if err != nil {
		t.Fatal(err)
	}
	first, err := keyfile.Read(path, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(first), "UEM_AUTH") || strings.Contains(string(first), string(seed)) {
		t.Fatal("broker configuration missing account or exposing private seed")
	}
	public, _ := issuer.PublicKey()
	if !strings.Contains(string(first), public) {
		t.Fatal("partial setup replaced existing issuer")
	}
	names := []string{"authorization-issuer.seed", "authorization-user.seed", "revocation-user.seed", "worker-user.seed", "console-user.seed", "provisioner-user.seed"}
	seeds := map[string][]byte{}
	for _, name := range names {
		data, err := keyfile.Read(filepath.Join(directory, name), 512)
		if err != nil {
			t.Fatal("setup did not protect credential", name, err)
		}
		seeds[name] = data
		key, err := nkeys.FromSeed(data)
		if err != nil {
			t.Fatal(err)
		}
		public, _ := key.PublicKey()
		key.Wipe()
		if !strings.Contains(string(first), public) || strings.Contains(string(first), string(data)) {
			t.Fatal("public configuration does not match private service identity", name)
		}
	}
	if _, err = Initialize(directory, config); err != nil {
		t.Fatal("identical setup retry failed", err)
	}
	second, err := keyfile.Read(path, 64<<10)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("retry changed broker configuration", err)
	}
	for name, before := range seeds {
		after, err := keyfile.Read(filepath.Join(directory, name), 512)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("retry rotated a service key", name, err)
		}
	}
	changed := config
	changed.Listen = "127.0.0.1:4223"
	if _, err = Initialize(directory, changed); !errors.Is(err, ErrSetup) {
		t.Fatal("conflicting setup silently rewrote existing configuration", err)
	}
	if err = os.Remove(filepath.Join(directory, "worker-user.seed")); err != nil {
		t.Fatal(err)
	}
	if _, err = Initialize(directory, config); !errors.Is(err, ErrSetup) {
		t.Fatal("installed identity loss silently generated a replacement key", err)
	}
	if _, err = os.Stat(filepath.Join(directory, "worker-user.seed")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing installed key was regenerated")
	}
}

func TestSetupRejectsInvalidInputBeforeCreatingKeys(t *testing.T) {
	config := setupConfig(t)
	config.Listen = "0.0.0.0:0"
	directory := filepath.Join(t.TempDir(), "invalid")
	if _, err := Initialize(directory, config); err == nil {
		t.Fatal("invalid broker listener accepted")
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid setup wrote credentials")
	}
}
