//go:build linux || darwin

package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
)

var ErrUpgrade = errors.New("broker upgrade requires an unchanged supported configuration and complete private service identities")
var ErrUpgradeLocked = errors.New("another broker configuration upgrade holds the directory lease")

var serviceSeeds = []string{"authorization-issuer.seed", "authorization-user.seed", "revocation-user.seed", "worker-user.seed", "console-user.seed", "provisioner-user.seed"}
var originalOperations = []string{"report", "deployresult", "agentconfig", "wingetcfg.profiles", "ansiblecfg.profiles", "wingetcfg.deploy", "wingetcfg.exclude", "wingetcfg.report"}
var previousOperations = []string{"report", "hardware", "recovery", "rotation", "deployresult", "agentconfig", "wingetcfg.profiles", "ansiblecfg.profiles", "wingetcfg.deploy", "wingetcfg.exclude", "wingetcfg.report"}
var upgradedOperations = []string{"report", "hardware", "recovery", "rotation", "software", "deployresult", "agentconfig", "wingetcfg.profiles", "ansiblecfg.profiles", "wingetcfg.deploy", "wingetcfg.exclude", "wingetcfg.report"}

const upgradeJournal = "broker-upgrade-v2.json"
const upgradeBackup = "broker-before-v2.json"
const upgradeNext = "broker-next-v2.json"
const upgradeComplete = "broker-upgrade-v2.complete.json"
const upgradeLock = "broker-upgrade.lock"

const priorJournal = "broker-upgrade-v1.json"
const priorBackup = "broker-before-v1.json"
const priorNext = "broker-next-v1.json"
const priorComplete = "broker-upgrade-v1.complete.json"

type UpgradePlan struct {
	Version             int      `json:"version"`
	Before              string   `json:"before_sha256"`
	After               string   `json:"after_sha256"`
	ChangeRequired      bool     `json:"change_required"`
	AddedWorkerRequests []string `json:"added_worker_requests"`
}

type upgradeRecord struct {
	Version int    `json:"version"`
	Before  string `json:"before_sha256"`
	After   string `json:"after_sha256"`
}

type upgradeSnapshot struct {
	current, legacy, target []byte
	added                   []string
}

func digest(data []byte) string { hash := sha256.Sum256(data); return hex.EncodeToString(hash[:]) }
func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func (s upgradeSnapshot) plan() UpgradePlan {
	plan := UpgradePlan{Version: 2, Before: digest(s.current), After: digest(s.target), ChangeRequired: !bytes.Equal(s.current, s.target), AddedWorkerRequests: []string{}}
	if plan.ChangeRequired {
		plan.AddedWorkerRequests = slices.Clone(s.added)
	}
	return plan
}

// PlanUpgrade reads existing configuration and identities without creating or
// changing any file. Only the two known preceding worker grants and the current exact
// generated configuration are recognized; custom changes are never merged.
func PlanUpgrade(ctx context.Context, directory string) (UpgradePlan, error) {
	if err := ctx.Err(); err != nil {
		return UpgradePlan{}, err
	}
	d, err := openUpgradeDirectory(directory, false)
	if err != nil {
		return UpgradePlan{}, err
	}
	defer d.close()
	snapshot, err := inspectUpgrade(d)
	if err != nil {
		return UpgradePlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return UpgradePlan{}, err
	}
	return snapshot.plan(), nil
}

// Upgrade installs the reviewed worker grant while retaining the exact original
// keys, listeners, TLS references and JetStream path. expected is the preview's
// before_sha256. A private journal and original configuration survive a crash.
// The command does not signal/restart NATS. Deployments must reopen and verify
// the mounted configuration before reporting readiness; bind mount behavior
// across atomic replacement depends on the container runtime.
func Upgrade(ctx context.Context, directory, expected string) (UpgradePlan, error) {
	return upgrade(ctx, directory, expected, nil)
}

func upgrade(ctx context.Context, directory, expected string, afterWrite func(string) error) (UpgradePlan, error) {
	if !validDigest(expected) {
		return UpgradePlan{}, ErrUpgrade
	}
	if err := ctx.Err(); err != nil {
		return UpgradePlan{}, err
	}
	// Reject unsupported inputs before even creating a lease file.
	preflight, err := PlanUpgrade(ctx, directory)
	if err != nil {
		return UpgradePlan{}, err
	}
	if preflight.ChangeRequired && expected != preflight.Before {
		return UpgradePlan{}, ErrUpgrade
	}
	d, err := openUpgradeDirectory(directory, true)
	if err != nil {
		return UpgradePlan{}, err
	}
	defer d.close()
	d.ctx, d.afterWrite = ctx, afterWrite
	state, err := inspectUpgrade(d)
	if err != nil || state.plan().Before != preflight.Before {
		return UpgradePlan{}, ErrUpgrade
	}
	present, err := d.inventory()
	if err != nil {
		return UpgradePlan{}, err
	}
	record := upgradeRecord{Version: 2, Before: digest(state.legacy), After: digest(state.target)}
	encoded, _ := json.Marshal(record)
	if !present[upgradeJournal] {
		if present[upgradeBackup] || present[upgradeNext] || present[upgradeComplete] || expected != digest(state.current) {
			return UpgradePlan{}, ErrUpgrade
		}
		if bytes.Equal(state.current, state.target) {
			return state.plan(), nil
		}
		if err := d.write(upgradeJournal, encoded); err != nil {
			return UpgradePlan{}, err
		}
	} else {
		actual, err := d.read(upgradeJournal, 1024)
		if err != nil || !bytes.Equal(actual, encoded) {
			return UpgradePlan{}, ErrUpgrade
		}
	}
	if expected != record.Before && (expected != record.After || !bytes.Equal(state.current, state.target)) {
		return UpgradePlan{}, ErrUpgrade
	}
	if present[upgradeBackup] {
		actual, err := d.read(upgradeBackup, 64<<10)
		if err != nil || !bytes.Equal(actual, state.legacy) {
			return UpgradePlan{}, ErrUpgrade
		}
	} else {
		if !bytes.Equal(state.current, state.legacy) || present[upgradeComplete] || present[upgradeNext] {
			return UpgradePlan{}, ErrUpgrade
		}
		if err := d.write(upgradeBackup, state.legacy); err != nil {
			return UpgradePlan{}, err
		}
	}
	if bytes.Equal(state.current, state.legacy) {
		if present[upgradeComplete] {
			return UpgradePlan{}, ErrUpgrade
		}
		if present[upgradeNext] {
			actual, err := d.read(upgradeNext, 64<<10)
			if err != nil || !bytes.Equal(actual, state.target) {
				return UpgradePlan{}, ErrUpgrade
			}
		} else if err := d.write(upgradeNext, state.target); err != nil {
			return UpgradePlan{}, err
		}
		current, err := inspectUpgrade(d)
		if err != nil || !bytes.Equal(current.current, state.current) || !bytes.Equal(current.target, state.target) {
			return UpgradePlan{}, ErrUpgrade
		}
		for name, wanted := range map[string][]byte{upgradeJournal: encoded, upgradeBackup: state.legacy, upgradeNext: state.target} {
			actual, err := d.read(name, 64<<10)
			if err != nil || !bytes.Equal(actual, wanted) {
				return UpgradePlan{}, ErrUpgrade
			}
		}
		if err := d.publish(); err != nil {
			return UpgradePlan{}, err
		}
	} else if present[upgradeNext] {
		return UpgradePlan{}, ErrUpgrade
	}
	if err := d.sync(); err != nil {
		return UpgradePlan{}, err
	}
	if present[upgradeComplete] {
		actual, err := d.read(upgradeComplete, 1024)
		if err != nil || !bytes.Equal(actual, encoded) {
			return UpgradePlan{}, ErrUpgrade
		}
	} else if err := d.write(upgradeComplete, encoded); err != nil {
		return UpgradePlan{}, err
	}
	complete, err := d.read(upgradeComplete, 1024)
	if err != nil || !bytes.Equal(complete, encoded) {
		return UpgradePlan{}, ErrUpgrade
	}
	final, err := inspectUpgrade(d)
	if err != nil || !bytes.Equal(final.current, state.target) {
		return UpgradePlan{}, ErrUpgrade
	}
	return UpgradePlan{Version: 2, Before: expected, After: record.After, ChangeRequired: false, AddedWorkerRequests: []string{}}, nil
}

func inspectUpgrade(d *upgradeDirectory) (upgradeSnapshot, error) {
	var result upgradeSnapshot
	present, err := d.inventory()
	if err != nil {
		return result, err
	}
	if !slices.Equal(enrollment.Operations(), upgradedOperations) {
		return result, ErrUpgrade
	}
	actual, err := d.read("broker.json", 64<<10)
	if err != nil {
		return result, err
	}
	// The exact rendered comparison below rejects duplicate/unknown JSON fields,
	// formatting drift, altered limits, account policies and permission changes.
	var fields struct {
		Name   string `json:"server_name"`
		Listen string `json:"listen"`
		TLS    struct {
			Certificate string `json:"cert_file"`
			Key         string `json:"key_file"`
		} `json:"tls"`
		Websocket struct {
			Listen string `json:"listen"`
			TLS    struct {
				CA string `json:"ca_file"`
			} `json:"tls"`
		} `json:"websocket"`
		Jetstream struct {
			Directory string `json:"store_dir"`
		} `json:"jetstream"`
	}
	if json.Unmarshal(actual, &fields) != nil {
		return result, ErrUpgrade
	}
	public := make([]string, len(serviceSeeds))
	for i, name := range serviceSeeds {
		seed, err := d.read(name, 512)
		if err != nil {
			return result, err
		}
		key, err := nkeys.FromSeed(bytes.TrimSpace(seed))
		clear(seed)
		if err != nil {
			return result, ErrUpgrade
		}
		public[i], err = key.PublicKey()
		key.Wipe()
		if err != nil || i == 0 && !nkeys.IsValidPublicAccountKey(public[i]) || i > 0 && !nkeys.IsValidPublicUserKey(public[i]) {
			return result, ErrUpgrade
		}
	}
	config := enrollment.BrokerConfiguration{Name: fields.Name, Listen: fields.Listen, WebsocketListen: fields.Websocket.Listen,
		CertificateFile: fields.TLS.Certificate, KeyFile: fields.TLS.Key, GatewayCAFile: fields.Websocket.TLS.CA, StoreDirectory: fields.Jetstream.Directory,
		Issuer: public[0], AuthorizationUser: public[1], RevocationUser: public[2], WorkerUser: public[3], ConsoleUser: public[4], ProvisionerUser: public[5]}
	target, err := config.Render()
	if err != nil {
		return result, ErrUpgrade
	}
	original, err := precedingWorkerGrant(target)
	if err != nil {
		return result, ErrUpgrade
	}
	previous, err := workerGrant(target, previousOperations)
	if err != nil || !bytes.Equal(actual, original) && !bytes.Equal(actual, previous) && !bytes.Equal(actual, target) {
		return result, ErrUpgrade
	}
	// Retain a completed v1 migration verbatim. An interrupted v1 migration must
	// first be resumed by its original distribution; a new review cannot rewrite
	// its immutable target or consume its staging file.
	prior := present[priorJournal] || present[priorBackup] || present[priorNext] || present[priorComplete]
	if prior {
		if present[priorNext] || !present[priorJournal] || !present[priorBackup] || !present[priorComplete] || bytes.Equal(actual, original) {
			return result, ErrUpgrade
		}
		record, _ := json.Marshal(upgradeRecord{Version: 1, Before: digest(original), After: digest(previous)})
		for name, wanted := range map[string][]byte{priorJournal: record, priorBackup: original, priorComplete: record} {
			retained, err := d.read(name, 64<<10)
			if err != nil || !bytes.Equal(retained, wanted) {
				return result, ErrUpgrade
			}
		}
	}
	legacy := actual
	if present[upgradeJournal] {
		encoded, err := d.read(upgradeJournal, 1024)
		if err != nil {
			return result, ErrUpgrade
		}
		var record upgradeRecord
		if json.Unmarshal(encoded, &record) != nil {
			return result, ErrUpgrade
		}
		switch record.Before {
		case digest(original):
			if prior {
				return result, ErrUpgrade
			}
			legacy = original
		case digest(previous):
			legacy = previous
		default:
			return result, ErrUpgrade
		}
		wanted, _ := json.Marshal(upgradeRecord{Version: 2, Before: digest(legacy), After: digest(target)})
		if !bytes.Equal(encoded, wanted) || !bytes.Equal(actual, legacy) && !bytes.Equal(actual, target) {
			return result, ErrUpgrade
		}
	}
	added := []string{"software"}
	if bytes.Equal(legacy, original) {
		added = []string{"hardware", "recovery", "rotation", "software"}
	}
	return upgradeSnapshot{current: actual, legacy: legacy, target: target, added: added}, nil
}

// The preceding initializer used shared commit 5083e68c8f76. Its renderer is
// identical except for these eight worker subjects (enrollment/subjects.go).
func precedingWorkerGrant(target []byte) ([]byte, error) {
	return workerGrant(target, originalOperations)
}

func workerGrant(target []byte, operations []string) ([]byte, error) {
	var document map[string]any
	if json.Unmarshal(target, &document) != nil {
		return nil, ErrUpgrade
	}
	accounts, ok := document["accounts"].(map[string]any)
	if !ok {
		return nil, ErrUpgrade
	}
	devices, ok := accounts["UEM_DEVICES"].(map[string]any)
	if !ok {
		return nil, ErrUpgrade
	}
	users, ok := devices["users"].([]any)
	if !ok || len(users) != 3 {
		return nil, ErrUpgrade
	}
	worker, ok := users[0].(map[string]any)
	if !ok {
		return nil, ErrUpgrade
	}
	permissions, ok := worker["permissions"].(map[string]any)
	if !ok {
		return nil, ErrUpgrade
	}
	subjects := make([]string, len(operations))
	for i, operation := range operations {
		subjects[i] = "uem.v1.agent.*.request." + operation
	}
	permissions["subscribe"] = subjects
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if encoder.Encode(document) != nil {
		return nil, ErrUpgrade
	}
	return output.Bytes(), nil
}
