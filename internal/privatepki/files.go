//go:build linux || darwin

package privatepki

import (
	"errors"
	"io"
	"os"
	"syscall"
)

type directory struct {
	path  string
	root  *os.Root
	info  os.FileInfo
	lease *os.File
}

func protected(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid())) && info.Mode().Perm()&0077 == 0 && (info.IsDir() || stat.Nlink == 1)
}

func openDirectory(path string) (*directory, error) {
	if !validPath(path) {
		return nil, ErrConfiguration
	}
	// The caller selects an existing trusted parent. Do not recursively create
	// or change the permissions of unrelated deployment directories.
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, ErrState
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || !protected(info) {
		return nil, ErrState
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, ErrState
	}
	d := &directory{path: path, root: root, info: info}
	ready := false
	defer func() {
		if !ready {
			d.close()
		}
	}()
	d.lease, err = root.OpenFile("setup.lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, ErrState
	}
	leaseInfo, err := d.lease.Stat()
	if err != nil || !leaseInfo.Mode().IsRegular() || !protected(leaseInfo) {
		return nil, ErrState
	}
	if err := syscall.Flock(int(d.lease.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, ErrState
	}
	if d.unchanged() != nil {
		return nil, ErrState
	}
	ready = true
	return d, nil
}

func (d *directory) close() {
	if d.lease != nil {
		_ = d.lease.Close()
	}
	if d.root != nil {
		_ = d.root.Close()
	}
}

func (d *directory) unchanged() error {
	actual, err := os.Lstat(d.path)
	if err != nil || !actual.IsDir() || !protected(actual) || !os.SameFile(d.info, actual) {
		return ErrState
	}
	held, err := d.root.Stat(".")
	if err != nil || !os.SameFile(d.info, held) {
		return ErrState
	}
	leaseInfo, err := d.lease.Stat()
	if err != nil || !protected(leaseInfo) {
		return ErrState
	}
	current, err := d.root.Lstat("setup.lock")
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(leaseInfo, current) {
		return ErrState
	}
	return nil
}

func (d *directory) read(path string, limit int64) ([]byte, error) {
	if d.unchanged() != nil {
		return nil, ErrState
	}
	file, err := d.root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrState
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !protected(info) || info.Size() < 1 || info.Size() > limit {
		return nil, ErrState
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, ErrState
	}
	return data, nil
}

func (d *directory) write(path string, data []byte) error {
	if d.unchanged() != nil {
		return ErrState
	}
	file, err := d.root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return ErrState
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return ErrState
	}
	return nil
}

func (d *directory) sync(path string) error {
	if d.unchanged() != nil {
		return ErrState
	}
	file, err := d.root.Open(path)
	if err != nil {
		return ErrState
	}
	err = file.Sync()
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return ErrState
	}
	return nil
}
