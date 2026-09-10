//go:build linux || darwin

package broker

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

type upgradeDirectory struct {
	path       string
	root       *os.Root
	info       os.FileInfo
	lease      *os.File
	ctx        context.Context
	afterWrite func(string) error
}

func privateUpgradeEntry(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid())) && info.Mode().Perm()&0077 == 0 && (info.IsDir() || stat.Nlink == 1)
}

func openUpgradeDirectory(path string, locked bool) (*upgradeDirectory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == filepath.Dir(path) {
		return nil, ErrUpgrade
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || !privateUpgradeEntry(info) {
		return nil, ErrUpgrade
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, ErrUpgrade
	}
	d := &upgradeDirectory{path: path, root: root, info: info, ctx: context.Background()}
	ready := false
	defer func() {
		if !ready {
			d.close()
		}
	}()
	if _, err := d.inventory(); err != nil {
		return nil, err
	}
	if locked {
		d.lease, err = root.OpenFile(upgradeLock, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
		if err != nil {
			return nil, ErrUpgrade
		}
		info, err := d.lease.Stat()
		if err != nil || !info.Mode().IsRegular() || !privateUpgradeEntry(info) {
			return nil, ErrUpgrade
		}
		if err := syscall.Flock(int(d.lease.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			if errors.Is(err, syscall.EWOULDBLOCK) {
				return nil, ErrUpgradeLocked
			}
			return nil, ErrUpgrade
		}
	}
	if err := d.check(); err != nil {
		return nil, err
	}
	ready = true
	return d, nil
}

func (d *upgradeDirectory) close() {
	if d.lease != nil {
		_ = d.lease.Close()
	}
	_ = d.root.Close()
}
func (d *upgradeDirectory) check() error {
	if err := d.ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(d.path)
	if err != nil || !info.IsDir() || !privateUpgradeEntry(info) || !os.SameFile(d.info, info) {
		return ErrUpgrade
	}
	held, err := d.root.Stat(".")
	if err != nil || !os.SameFile(d.info, held) {
		return ErrUpgrade
	}
	if d.lease != nil {
		held, err := d.lease.Stat()
		current, other := d.root.Lstat(upgradeLock)
		if err != nil || other != nil || !current.Mode().IsRegular() || !privateUpgradeEntry(current) || !os.SameFile(held, current) {
			return ErrUpgrade
		}
	}
	return nil
}
func (d *upgradeDirectory) inventory() (map[string]bool, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	file, err := d.root.Open(".")
	if err != nil {
		return nil, ErrUpgrade
	}
	defer file.Close()
	names := append([]string{"broker.json", upgradeLock, upgradeJournal, upgradeBackup, upgradeNext, upgradeComplete}, serviceSeeds...)
	entries, err := file.ReadDir(len(names) + 1)
	if err != nil && err != io.EOF || len(entries) > len(names) {
		return nil, ErrUpgrade
	}
	result := map[string]bool{}
	for _, entry := range entries {
		if !slices.Contains(names, entry.Name()) {
			return nil, ErrUpgrade
		}
		result[entry.Name()] = true
	}
	return result, nil
}
func (d *upgradeDirectory) read(name string, limit int64) ([]byte, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	file, err := d.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrUpgrade
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !privateUpgradeEntry(info) || info.Size() < 1 || info.Size() > limit {
		return nil, ErrUpgrade
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, ErrUpgrade
	}
	return data, nil
}
func (d *upgradeDirectory) sync() error {
	if err := d.check(); err != nil {
		return err
	}
	file, err := d.root.Open(".")
	if err != nil {
		return ErrUpgrade
	}
	err = file.Sync()
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return ErrUpgrade
	}
	return nil
}
func (d *upgradeDirectory) write(name string, data []byte) error {
	if err := d.check(); err != nil {
		return err
	}
	file, err := d.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return ErrUpgrade
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return ErrUpgrade
	}
	if err := d.sync(); err != nil {
		return err
	}
	if d.afterWrite != nil {
		return d.afterWrite(name)
	}
	return nil
}
func (d *upgradeDirectory) publish() error {
	if err := d.check(); err != nil {
		return err
	}
	if err := d.root.Rename(upgradeNext, "broker.json"); err != nil {
		return ErrUpgrade
	}
	if err := d.sync(); err != nil {
		return err
	}
	if d.afterWrite != nil {
		return d.afterWrite("broker.json")
	}
	return nil
}
