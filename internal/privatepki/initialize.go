//go:build linux || darwin

package privatepki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"
)

type binding struct {
	Installation string    `json:"installation"`
	CreatedAt    time.Time `json:"created_at"`
	Config       Config    `json:"config"`
}

type Manifest struct {
	Version      int               `json:"version"`
	Installation string            `json:"installation"`
	NotAfter     time.Time         `json:"not_after"`
	Files        map[string]string `json:"files"`
}

var directories = []string{"authority", "console", "broker", "gateway", "trust"}

// Order is a durable initialization journal: only a missing suffix can be
// completed. A hole followed by existing material is never treated as a new key.
var artifacts = []string{
	"authority/ca.key", "authority/ca.pem", "console/server.key", "console/server.pem",
	"broker/server.key", "broker/server.pem", "gateway/client.key", "gateway/client.pem",
	"gateway/backend-ca.pem", "console/gateway-leaves.pem", "broker/gateway-leaves.pem", "trust/backend-ca.pem",
}

// Initialize creates or verifies one complete private PKI. It does not replace,
// renew, install into host trust, publish DNS, or contact a database/remote service.
// Consumers must wait for successful completion and never mount authority/.
func Initialize(ctx context.Context, path string, config Config) (*Manifest, error) {
	c, err := config.normalized()
	if err != nil || !validPath(path) {
		return nil, ErrConfiguration
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	d, err := openDirectory(path)
	if err != nil {
		return nil, err
	}
	defer d.close()
	return initialize(ctx, d, c, time.Now().UTC().Truncate(time.Second), nil)
}

func initialize(ctx context.Context, d *directory, config Config, now time.Time, afterWrite func(string) error) (*Manifest, error) {
	directories, artifacts := config.layout()
	present, err := inventory(d, config)
	if err != nil {
		return nil, err
	}
	b, err := bind(d, config, now, present)
	if err != nil {
		return nil, err
	}
	committed := present["manifest.json"]
	missing := false
	for _, path := range artifacts {
		if present[path] {
			if missing {
				return nil, ErrState
			}
		} else {
			missing = true
		}
	}
	if committed && missing {
		return nil, ErrState
	}
	identity, err := loadIdentity(ctx, d, b, now, present)
	if err != nil {
		return nil, err
	}
	defer identity.clear()
	for _, name := range directories {
		if !present[name] {
			if d.unchanged() != nil || d.root.Mkdir(name, 0700) != nil || d.sync(".") != nil {
				return nil, ErrState
			}
		}
	}
	data := make(map[string][]byte, len(artifacts))
	defer func() {
		for _, value := range data {
			clear(value)
		}
	}()
	for _, path := range artifacts {
		expected := identity.Files[path]
		if source, copied := trustSources[path]; copied {
			expected = identity.Files[source]
		}
		if len(expected) == 0 {
			return nil, ErrState
		}
		value, err := ensure(ctx, d, path, present[path], func() ([]byte, error) { return bytes.Clone(expected), nil }, afterWrite)
		if err != nil {
			return nil, err
		}
		data[path] = value
		if !bytes.Equal(value, expected) {
			return nil, ErrState
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// Re-read every file and directory before the final readiness marker. A
	// matching manifest is also required on later invocations, never rewritten.
	if _, err := inventory(d, config); err != nil {
		return nil, err
	}
	manifest := Manifest{Version: 1, Installation: b.Installation, NotAfter: b.CreatedAt.AddDate(1, 0, 0), Files: map[string]string{}}
	for _, path := range artifacts {
		actual, err := d.read(path, 64<<10)
		if err != nil {
			return nil, err
		}
		equal := bytes.Equal(actual, data[path])
		clear(actual)
		if !equal {
			return nil, ErrState
		}
		digest := sha256.Sum256(data[path])
		manifest.Files[path] = hex.EncodeToString(digest[:])
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, ErrState
	}
	if committed {
		actual, err := d.read("manifest.json", 16<<10)
		if err != nil || !bytes.Equal(actual, encoded) {
			return nil, ErrState
		}
	} else {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err := d.write("manifest.json", encoded); err != nil {
			return nil, err
		}
	}
	for _, path := range directories {
		if d.sync(path) != nil {
			return nil, ErrState
		}
	}
	if d.sync(".") != nil {
		return nil, ErrState
	}
	return &manifest, nil
}

func ensure(ctx context.Context, d *directory, path string, exists bool, generate func() ([]byte, error), afterWrite func(string) error) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if exists {
		return d.read(path, 64<<10)
	}
	value, err := generate()
	if err != nil {
		return nil, ErrCertificate
	}
	if ctx.Err() != nil {
		clear(value)
		return nil, ctx.Err()
	}
	if err := d.write(path, value); err != nil {
		clear(value)
		return nil, err
	}
	if d.sync(filepath.Dir(path)) != nil {
		clear(value)
		return nil, ErrState
	}
	if afterWrite != nil {
		if err := afterWrite(path); err != nil {
			clear(value)
			return nil, err
		}
	}
	return value, nil
}

func bind(d *directory, config Config, now time.Time, present map[string]bool) (binding, error) {
	var b binding
	if present["configuration.json"] {
		data, err := d.read("configuration.json", 8192)
		if err != nil || json.Unmarshal(data, &b) != nil {
			return b, ErrState
		}
		id, err := hex.DecodeString(b.Installation)
		if err != nil || len(id) != 16 || hex.EncodeToString(id) != b.Installation || b.CreatedAt.IsZero() || !b.CreatedAt.Equal(b.CreatedAt.UTC().Truncate(time.Second)) {
			return b, ErrState
		}
		b.Config = config
		expected, err := json.Marshal(b)
		if err != nil || !bytes.Equal(data, expected) {
			return b, ErrState
		}
		return b, nil
	}
	if len(present) != 1 || !present["setup.lock"] {
		return b, ErrState
	}
	identifier := make([]byte, 16)
	if _, err := rand.Read(identifier); err != nil {
		return b, ErrState
	}
	b = binding{Installation: hex.EncodeToString(identifier), CreatedAt: now, Config: config}
	encoded, err := json.Marshal(b)
	if err != nil || d.write("configuration.json", encoded) != nil || d.sync(".") != nil {
		return b, ErrState
	}
	return b, nil
}

// The layout is fixed and shallow. Unknown entries, links, non-private paths and
// extra data are rejected without deleting or chmod-ing anything.
func inventory(d *directory, config Config) (map[string]bool, error) {
	directories, artifacts := config.layout()
	if d.unchanged() != nil {
		return nil, ErrState
	}
	result := map[string]bool{}
	for _, parent := range append([]string{"."}, directories...) {
		info, err := d.root.Lstat(parent)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() || !protected(info) {
			return nil, ErrState
		}
		file, err := d.root.Open(parent)
		if err != nil {
			return nil, ErrState
		}
		entries, err := file.ReadDir(17)
		file.Close()
		if (err != nil && err != io.EOF) || len(entries) > 16 {
			return nil, ErrState
		}
		for _, entry := range entries {
			path := filepath.ToSlash(filepath.Join(parent, entry.Name()))
			info, err := d.root.Lstat(path)
			if err != nil || !protected(info) {
				return nil, ErrState
			}
			if slices.Contains(directories, path) {
				if !info.IsDir() {
					return nil, ErrState
				}
			} else if path == "setup.lock" || path == "configuration.json" || path == "identity.json" || path == "manifest.json" || slices.Contains(artifacts, path) {
				if !info.Mode().IsRegular() {
					return nil, ErrState
				}
			} else {
				return nil, ErrState
			}
			result[path] = true
		}
	}
	return result, nil
}
