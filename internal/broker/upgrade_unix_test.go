//go:build linux || darwin

package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/open-uem/nats/enrollment"
)

func upgradeFixture(t *testing.T) (string, enrollment.BrokerConfiguration, []byte) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "broker")
	config := setupConfig(t)
	path, err := Initialize(directory, config)
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := precedingWorkerGrant(target)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(legacy, target) {
		t.Fatal("legacy fixture does not differ")
	}
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	return directory, config, target
}

func upgradeFiles(t *testing.T, directory string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				t.Fatal(err)
			}
			result[entry.Name()] = info.Mode().String() + link
		} else {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			result[entry.Name()] = info.Mode().String() + digest(data)
			clear(data)
		}
	}
	return result
}

func TestBrokerUpgradeRetainsIdentityAndOnlyAddsCurrentWorkerRequests(t *testing.T) {
	directory, config, target := upgradeFixture(t)
	before := upgradeFiles(t, directory)
	original, _ := os.ReadFile(filepath.Join(directory, "broker.json"))
	plan, err := PlanUpgrade(t.Context(), directory)
	if err != nil || !plan.ChangeRequired || plan.Before != digest(original) || plan.After != digest(target) || !slices.Equal(plan.AddedWorkerRequests, []string{"hardware", "recovery", "rotation"}) {
		t.Fatal("invalid upgrade preview", err)
	}
	if !reflect.DeepEqual(before, upgradeFiles(t, directory)) {
		t.Fatal("read-only preview changed state")
	}
	completed, err := Upgrade(t.Context(), directory, plan.Before)
	if err != nil || completed.ChangeRequired || completed.Before != plan.Before || completed.After != plan.After {
		t.Fatal("upgrade failed", err)
	}
	backup, err := os.ReadFile(filepath.Join(directory, upgradeBackup))
	if err != nil || !bytes.Equal(backup, original) {
		t.Fatal("original configuration was not retained")
	}
	actual, err := os.ReadFile(filepath.Join(directory, "broker.json"))
	if err != nil || !bytes.Equal(actual, target) {
		t.Fatal("upgrade did not install exact current grant")
	}
	// Independently inspect the only changed JSON location and all exact subjects.
	var oldDoc, newDoc map[string]any
	if json.Unmarshal(original, &oldDoc) != nil || json.Unmarshal(actual, &newDoc) != nil {
		t.Fatal("invalid configuration JSON")
	}
	permissions := func(doc map[string]any) map[string]any {
		return doc["accounts"].(map[string]any)["UEM_DEVICES"].(map[string]any)["users"].([]any)[0].(map[string]any)["permissions"].(map[string]any)
	}
	got := permissions(newDoc)["subscribe"].([]any)
	want := []string{"report", "hardware", "recovery", "rotation", "deployresult", "agentconfig", "wingetcfg.profiles", "ansiblecfg.profiles", "wingetcfg.deploy", "wingetcfg.exclude", "wingetcfg.report"}
	if len(got) != len(want) {
		t.Fatal("unexpected worker rights")
	}
	for i, operation := range want {
		if got[i] != "uem.v1.agent.*.request."+operation {
			t.Fatal("incorrect worker grant")
		}
	}
	permissions(oldDoc)["subscribe"] = permissions(newDoc)["subscribe"]
	if !reflect.DeepEqual(oldDoc, newDoc) {
		t.Fatal("upgrade changed unrelated settings or permissions")
	}
	after := upgradeFiles(t, directory)
	for _, name := range serviceSeeds {
		if before[name] != after[name] {
			t.Fatal("upgrade changed a service seed")
		}
	}
	for range 2 {
		again, err := Upgrade(t.Context(), directory, plan.Before)
		if err != nil || !reflect.DeepEqual(again, completed) || !reflect.DeepEqual(after, upgradeFiles(t, directory)) {
			t.Fatal("upgrade retry changed retained state", err)
		}
	}
	if _, err := Initialize(directory, config); err != nil {
		t.Fatal("ordinary initialization rejects upgraded configuration", err)
	}
	if _, err := Upgrade(t.Context(), directory, plan.After); err != nil {
		t.Fatal("current preview hash rejected after completed migration", err)
	}
	if !reflect.DeepEqual(after, upgradeFiles(t, directory)) {
		t.Fatal("current preview retry changed files")
	}
	current, err := PlanUpgrade(t.Context(), directory)
	if err != nil || current.ChangeRequired || current.Before != plan.After {
		t.Fatal("completed preview is wrong", err)
	}
}

func TestBrokerUpgradeInterruptedWritesAndPublication(t *testing.T) {
	for _, stop := range []string{upgradeJournal, upgradeBackup, upgradeNext, "broker.json", upgradeComplete} {
		t.Run(stop, func(t *testing.T) {
			directory, _, target := upgradeFixture(t)
			before := upgradeFiles(t, directory)
			plan, err := PlanUpgrade(t.Context(), directory)
			if err != nil {
				t.Fatal(err)
			}
			interrupted := errors.New("synthetic interrupted upgrade")
			_, err = upgrade(t.Context(), directory, plan.Before, func(name string) error {
				if name == stop {
					return interrupted
				}
				return nil
			})
			if !errors.Is(err, interrupted) {
				t.Fatal("interruption was not exercised", err)
			}
			partial := upgradeFiles(t, directory)
			if _, err := Upgrade(t.Context(), directory, plan.Before); err != nil {
				t.Fatal("upgrade could not resume", err)
			}
			actual, _ := os.ReadFile(filepath.Join(directory, "broker.json"))
			if !bytes.Equal(actual, target) {
				t.Fatal("resume installed incorrect configuration")
			}
			final := upgradeFiles(t, directory)
			for _, name := range serviceSeeds {
				if before[name] != final[name] {
					t.Fatal("resume replaced identity")
				}
			}
			for _, name := range []string{upgradeJournal, upgradeBackup, upgradeComplete} {
				if value, ok := partial[name]; ok && final[name] != value {
					t.Fatal("resume replaced completed upgrade material")
				}
			}
		})
	}
}

func TestBrokerUpgradeRejectsUnsupportedOrUnsafeSources(t *testing.T) {
	for _, kind := range []string{"missing seed", "partial seed", "seed symlink", "seed hardlink", "seed permissions", "directory permissions", "unknown file", "custom rights", "duplicate JSON", "changed JSON format", "config symlink"} {
		t.Run(kind, func(t *testing.T) {
			directory, _, _ := upgradeFixture(t)
			name := filepath.Join(directory, "worker-user.seed")
			config := filepath.Join(directory, "broker.json")
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "missing seed":
				must(os.Remove(name))
			case "partial seed":
				must(os.WriteFile(name, []byte("SU"), 0600))
			case "seed symlink":
				must(os.Remove(name))
				must(os.Symlink(filepath.Join(directory, "console-user.seed"), name))
			case "seed hardlink":
				must(os.Link(name, filepath.Join(t.TempDir(), "seed")))
			case "seed permissions":
				must(os.Chmod(name, 0644))
			case "directory permissions":
				must(os.Chmod(directory, 0755))
			case "unknown file":
				must(os.WriteFile(filepath.Join(directory, "unrelated"), []byte("retained"), 0600))
			case "custom rights":
				data, _ := os.ReadFile(config)
				must(os.WriteFile(config, bytes.Replace(data, []byte(`"max_connections": 8192`), []byte(`"max_connections": 8193`), 1), 0600))
			case "duplicate JSON":
				data, _ := os.ReadFile(config)
				must(os.WriteFile(config, append([]byte(`{"max_connections":8192,`), data[1:]...), 0600))
			case "changed JSON format":
				data, _ := os.ReadFile(config)
				must(os.WriteFile(config, bytes.TrimSpace(data), 0600))
			case "config symlink":
				must(os.Rename(config, filepath.Join(t.TempDir(), "saved.json")))
				must(os.Symlink(name, config))
			}
			before := upgradeFiles(t, directory)
			if _, err := PlanUpgrade(t.Context(), directory); err == nil {
				t.Fatal("unsafe source accepted by preview")
			}
			if _, err := Upgrade(t.Context(), directory, strings.Repeat("a", 64)); err == nil {
				t.Fatal("unsafe source accepted")
			}
			if !reflect.DeepEqual(before, upgradeFiles(t, directory)) {
				t.Fatal("rejection changed source files")
			}
		})
	}
}

func TestBrokerUpgradeRejectsDamagedJournalAndRollback(t *testing.T) {
	for _, kind := range []string{"missing journal", "missing backup", "partial journal", "partial backup", "partial next", "unknown journal field", "wrong expected hash", "committed rollback", "committed missing backup", "committed missing journal", "partial completion"} {
		t.Run(kind, func(t *testing.T) {
			directory, _, _ := upgradeFixture(t)
			plan, _ := PlanUpgrade(t.Context(), directory)
			_, err := upgrade(t.Context(), directory, plan.Before, func(name string) error {
				if name == upgradeNext {
					return errors.New("stop")
				}
				return nil
			})
			if err == nil {
				t.Fatal("fixture did not stop before publication")
			}
			if strings.HasPrefix(kind, "committed") || kind == "partial completion" {
				if _, err := Upgrade(t.Context(), directory, plan.Before); err != nil {
					t.Fatal(err)
				}
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			write := func(name string, data []byte) {
				t.Helper()
				must(os.WriteFile(filepath.Join(directory, name), data, 0600))
			}
			expected := plan.Before
			switch kind {
			case "missing journal", "committed missing journal":
				must(os.Remove(filepath.Join(directory, upgradeJournal)))
			case "missing backup", "committed missing backup":
				must(os.Remove(filepath.Join(directory, upgradeBackup)))
			case "partial journal":
				write(upgradeJournal, []byte(`{"version":`))
			case "partial backup":
				write(upgradeBackup, []byte(`{}`))
			case "partial next":
				write(upgradeNext, []byte(`{}`))
			case "unknown journal field":
				data, _ := os.ReadFile(filepath.Join(directory, upgradeJournal))
				write(upgradeJournal, append([]byte(`{"unknown":1,`), data[1:]...))
			case "wrong expected hash":
				expected = strings.Repeat("a", 64)
			case "committed rollback":
				data, _ := os.ReadFile(filepath.Join(directory, upgradeBackup))
				write("broker.json", data)
			case "partial completion":
				write(upgradeComplete, []byte(`{}`))
			}
			before := upgradeFiles(t, directory)
			if _, err := Upgrade(t.Context(), directory, expected); err == nil {
				t.Fatal("damaged upgrade accepted")
			}
			if !reflect.DeepEqual(before, upgradeFiles(t, directory)) {
				t.Fatal("damaged upgrade state was repaired or replaced")
			}
		})
	}
}

func TestBrokerUpgradeLeaseCancellationAndMutation(t *testing.T) {
	directory, _, _ := upgradeFixture(t)
	plan, _ := PlanUpgrade(t.Context(), directory)
	held, err := openUpgradeDirectory(directory, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Upgrade(t.Context(), directory, plan.Before); !errors.Is(err, ErrUpgradeLocked) {
		t.Fatal("directory lease was bypassed", err)
	}
	held.close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	before := upgradeFiles(t, directory)
	if _, err := Upgrade(ctx, directory, plan.Before); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled upgrade proceeded", err)
	}
	if !reflect.DeepEqual(before, upgradeFiles(t, directory)) {
		t.Fatal("cancelled upgrade wrote state")
	}
	var group sync.WaitGroup
	for range 5 {
		group.Go(func() {
			_, err := Upgrade(t.Context(), directory, plan.Before)
			if err != nil && !errors.Is(err, ErrUpgradeLocked) && !errors.Is(err, ErrUpgrade) {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if _, err := Upgrade(t.Context(), directory, plan.Before); err != nil {
		t.Fatal("concurrent upgrades damaged state", err)
	}
	for _, name := range []string{upgradeJournal, upgradeBackup, upgradeNext, "worker-user.seed", "broker.json"} {
		t.Run(name, func(t *testing.T) {
			directory, _, _ := upgradeFixture(t)
			plan, _ := PlanUpgrade(t.Context(), directory)
			original, _ := os.ReadFile(filepath.Join(directory, "broker.json"))
			_, err := upgrade(t.Context(), directory, plan.Before, func(completed string) error {
				if completed == upgradeNext {
					return os.WriteFile(filepath.Join(directory, name), []byte("synthetic changed state"), 0600)
				}
				return nil
			})
			if err == nil {
				t.Fatal("state changed before publication without rejection")
			}
			if name != "broker.json" {
				current, _ := os.ReadFile(filepath.Join(directory, "broker.json"))
				if !bytes.Equal(current, original) {
					t.Fatal("mutation published a new broker configuration")
				}
			}
		})
	}
}

func TestBrokerUpgradeCurrentAndReadOnlyPreview(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "current")
	path, err := Initialize(directory, setupConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(path)
	plan, err := Upgrade(t.Context(), directory, digest(current))
	if err != nil || plan.ChangeRequired {
		t.Fatal("current configuration rejected", err)
	}
	entries, _ := os.ReadDir(directory)
	for _, entry := range entries {
		if err := os.Chmod(filepath.Join(directory, entry.Name()), 0400); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(directory, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0700) })
	before := upgradeFiles(t, directory)
	if _, err := PlanUpgrade(t.Context(), directory); err != nil {
		t.Fatal("read-only preview failed", err)
	}
	if !reflect.DeepEqual(before, upgradeFiles(t, directory)) {
		t.Fatal("preview changed source")
	}
}
