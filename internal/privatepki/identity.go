//go:build linux || darwin

package privatepki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"time"
)

type identity struct {
	Installation string            `json:"installation"`
	Files        map[string][]byte `json:"files"`
}

func (i *identity) clear() {
	for _, data := range i.Files {
		clear(data)
	}
}

// Retain the entire original identity set in one durable private record before
// exporting any service file. Retrying an interrupted export never re-signs a
// gateway leaf or generates a different service key, even if its tail was lost.
func loadIdentity(ctx context.Context, d *directory, b binding, now time.Time, present map[string]bool) (*identity, error) {
	_, artifacts := b.Config.layout()
	roles := b.Config.roles()
	i := &identity{Installation: b.Installation, Files: map[string][]byte{}}
	ready := false
	defer func() {
		if !ready {
			i.clear()
		}
	}()
	if present["identity.json"] {
		data, err := d.read("identity.json", 128<<10)
		if err != nil {
			return nil, err
		}
		defer clear(data)
		if json.Unmarshal(data, i) != nil || i.Installation != b.Installation || len(i.Files) != 2*len(roles) {
			return nil, ErrState
		}
		canonical, err := json.Marshal(i)
		defer clear(canonical)
		if err != nil || !bytes.Equal(data, canonical) {
			return nil, ErrState
		}
	} else {
		if present["manifest.json"] {
			return nil, ErrState
		}
		for _, path := range artifacts {
			if present[path] {
				return nil, ErrState
			}
		}
		var authority *x509.Certificate
		var authorityKey crypto.Signer
		for _, role := range roles {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			keyPath, certPath := identityPaths(role)
			data, err := newKey(role == "console")
			if err != nil {
				return nil, ErrCertificate
			}
			i.Files[keyPath] = data
			key, err := readKey(data, role == "console")
			if err != nil {
				return nil, err
			}
			certificate, err := issue(b, role, key, authority, authorityKey)
			if err != nil {
				return nil, err
			}
			i.Files[certPath] = certificate
			cert, err := validateCertificate(b, role, certificate, key, authority, now)
			if err != nil {
				return nil, err
			}
			if role == "authority" {
				authority, authorityKey = cert, key
			}
		}
	}
	var authority *x509.Certificate
	seen := map[[32]byte]bool{}
	for _, role := range roles {
		keyPath, certPath := identityPaths(role)
		key, err := readKey(i.Files[keyPath], role == "console")
		if err != nil {
			return nil, err
		}
		public, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			return nil, ErrCertificate
		}
		fingerprint := sha256.Sum256(public)
		if seen[fingerprint] {
			return nil, ErrCertificate
		}
		seen[fingerprint] = true
		cert, err := validateCertificate(b, role, i.Files[certPath], key, authority, now)
		if err != nil {
			return nil, err
		}
		if role == "authority" {
			authority = cert
		}
	}
	if !present["identity.json"] {
		data, err := json.Marshal(i)
		defer clear(data)
		if err != nil {
			return nil, ErrState
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if d.write("identity.json", data) != nil || d.sync(".") != nil {
			return nil, ErrState
		}
	}
	ready = true
	return i, nil
}
