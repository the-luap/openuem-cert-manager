// Package broker initializes dedicated individual-agent service credentials.
package broker

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"

	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/keyfile"
)

var ErrSetup = errors.New("individual broker setup is incomplete, inaccessible or conflicts with existing configuration")

// Initialize retains existing protected service seeds and writes configuration
// only after every seed is durable. An identical retry is safe; changing an
// installed configuration requires a separate, deliberate rotation/reconfiguration.
func Initialize(directory string, config enrollment.BrokerConfiguration) (string, error) {
	if !filepath.IsAbs(directory) {
		return "", ErrSetup
	}
	// Validate all non-key parameters before creating files.
	signer, err := nkeys.CreateAccount()
	if err != nil {
		return "", ErrSetup
	}
	defer signer.Wipe()
	config.Issuer, _ = signer.PublicKey()
	userKeys := make([]nkeys.KeyPair, 5)
	public := make([]string, 5)
	for i := range userKeys {
		userKeys[i], err = nkeys.CreateUser()
		if err != nil {
			return "", ErrSetup
		}
		defer userKeys[i].Wipe()
		public[i], _ = userKeys[i].PublicKey()
	}
	config.AuthorizationUser, config.RevocationUser, config.WorkerUser, config.ConsoleUser, config.ProvisionerUser = public[0], public[1], public[2], public[3], public[4]
	if _, err = config.Render(); err != nil {
		return "", err
	}
	if err = os.MkdirAll(directory, 0700); err != nil {
		return "", ErrSetup
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrSetup
	}
	path := filepath.Join(directory, "broker.json")
	configInfo, err := os.Lstat(path)
	installed := err == nil
	if installed && !configInfo.Mode().IsRegular() {
		return "", ErrSetup
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", ErrSetup
	}
	load := func(name string, generated nkeys.KeyPair, account bool) (string, error) {
		filename := filepath.Join(directory, name)
		if !installed {
			seed, err := generated.Seed()
			if err != nil {
				return "", ErrSetup
			}
			_ = keyfile.Create(filename, seed)
			clear(seed)
		}
		info, err := os.Lstat(filename)
		if err != nil || !info.Mode().IsRegular() {
			return "", ErrSetup
		}
		seed, err := keyfile.Read(filename, 512)
		if err != nil {
			return "", ErrSetup
		}
		defer clear(seed)
		key, err := nkeys.FromSeed(bytes.TrimSpace(seed))
		if err != nil {
			return "", ErrSetup
		}
		defer key.Wipe()
		public, err := key.PublicKey()
		if err != nil || (account && !nkeys.IsValidPublicAccountKey(public)) || (!account && !nkeys.IsValidPublicUserKey(public)) {
			return "", ErrSetup
		}
		return public, nil
	}
	if config.Issuer, err = load("authorization-issuer.seed", signer, true); err != nil {
		return "", err
	}
	names := []string{"authorization-user.seed", "revocation-user.seed", "worker-user.seed", "console-user.seed", "provisioner-user.seed"}
	for i, name := range names {
		if public[i], err = load(name, userKeys[i], false); err != nil {
			return "", err
		}
	}
	config.AuthorizationUser, config.RevocationUser, config.WorkerUser, config.ConsoleUser, config.ProvisionerUser = public[0], public[1], public[2], public[3], public[4]
	encoded, err := config.Render()
	if err != nil {
		return "", err
	}
	// The configuration contains only public keys, but retaining private file
	// ownership also prevents a writable replacement from being accepted on retry.
	if !installed {
		_ = keyfile.Create(path, encoded)
	}
	actual, err := keyfile.Read(path, 64<<10)
	if err != nil || !bytes.Equal(actual, encoded) {
		return "", ErrSetup
	}
	return path, nil
}
