//go:build linux || darwin

package privatepki

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPrivatePKIDatabaseIdentityAndTLS(t *testing.T) {
	path, config := fixture(t)
	config.DatabaseNames = []string{"replica.internal", "database.internal"}
	original := slices.Clone(config.DatabaseNames)
	manifest, err := Initialize(t.Context(), path, config)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 14 || !slices.Equal(config.DatabaseNames, original) {
		t.Fatal("database identity is incomplete or mutated caller configuration")
	}
	before := snapshot(t, path)
	if _, err := Initialize(t.Context(), path, config); err != nil || !reflect.DeepEqual(before, snapshot(t, path)) {
		t.Fatal("database PKI retry changed an original identity", err)
	}
	identity, err := tls.LoadX509KeyPair(filepath.Join(path, "database/server.pem"), filepath.Join(path, "database/server.key"))
	if err != nil {
		t.Fatal("cannot load generated database identity", err)
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(path, "trust/backend-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		t.Fatal("missing generated database trust")
	}
	for _, name := range config.DatabaseNames {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Fatal("database SAN does not verify", err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("database server identity can authenticate as a client")
	}
	for _, name := range []string{"console/server.pem", "broker/server.pem", "gateway/client.pem"} {
		data, err := os.ReadFile(filepath.Join(path, name))
		if err != nil {
			t.Fatal(err)
		}
		der, err := decodeBlock(data, "CERTIFICATE")
		if err != nil {
			t.Fatal(err)
		}
		other, err := x509.ParseCertificate(der)
		if err != nil || bytes.Equal(leaf.RawSubjectPublicKeyInfo, other.RawSubjectPublicKeyInfo) {
			t.Fatal("database key is shared with another service")
		}
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ready") }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	for _, name := range []string{"database.internal", "replica.internal", "console.internal", "nats.internal", "wrong.internal"} {
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12}}
		client := &http.Client{Transport: transport, Timeout: time.Second}
		response, err := client.Get(server.URL)
		if err == nil {
			response.Body.Close()
		}
		transport.CloseIdleConnections()
		if (err == nil) != slices.Contains(config.DatabaseNames, name) {
			t.Fatal("TLS accepted a wrong database name or rejected a bound name")
		}
	}
	assertTLS(t, path)
}

func TestPrivatePKIDatabaseConfigurationAndCompatibility(t *testing.T) {
	for _, names := range [][]string{{"console.internal"}, {"nats.internal"}, {"database.internal", "database.internal"}, {"*.internal"}, {"Database.internal"}, {"127.0.0.1"}, {"database"}, {""}, strings.Split(strings.Repeat("db.internal,", 8)+"last.internal", ",")} {
		_, config := fixture(t)
		config.DatabaseNames = names
		if _, err := config.normalized(); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid or overlapping database names accepted")
		}
	}
	for _, existingDatabase := range []bool{false, true} {
		path, config := fixture(t)
		if existingDatabase {
			config.DatabaseNames = []string{"database.internal"}
		}
		if _, err := Initialize(t.Context(), path, config); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t, path)
		changed := config
		if existingDatabase {
			changed.DatabaseNames = nil
		} else {
			changed.DatabaseNames = []string{"database.internal"}
		}
		if _, err := Initialize(t.Context(), path, changed); !errors.Is(err, ErrState) || !reflect.DeepEqual(before, snapshot(t, path)) {
			t.Fatal("database mode silently changed an existing PKI", err)
		}
		changed.DatabaseNames = []string{"different.internal"}
		if _, err := Initialize(t.Context(), path, changed); !errors.Is(err, ErrState) || !reflect.DeepEqual(before, snapshot(t, path)) {
			t.Fatal("database names silently changed an existing PKI", err)
		}
		if _, err := Initialize(t.Context(), path, config); err != nil {
			t.Fatal("original configuration no longer resumes", err)
		}
		if !existingDatabase {
			data, err := os.ReadFile(filepath.Join(path, "configuration.json"))
			if err != nil || bytes.Contains(data, []byte("database_names")) {
				t.Fatal("legacy configuration encoding changed")
			}
		}
	}
}

func TestPrivatePKIDatabaseInterruptedExports(t *testing.T) {
	_, config := fixture(t)
	config.DatabaseNames = []string{"database.internal"}
	_, files := config.layout()
	for _, point := range files {
		t.Run(point, func(t *testing.T) {
			path, _ := fixture(t)
			d, err := openDirectory(path)
			if err != nil {
				t.Fatal(err)
			}
			defer d.close()
			interrupted := errors.New("synthetic database certificate interruption")
			_, err = initialize(t.Context(), d, config, time.Now().UTC().Truncate(time.Second), func(name string) error {
				if name == point {
					return interrupted
				}
				return nil
			})
			if !errors.Is(err, interrupted) {
				t.Fatal("database export interruption was not reached", err)
			}
			before := snapshot(t, path)
			if _, err := initialize(t.Context(), d, config, time.Now().UTC().Truncate(time.Second), nil); err != nil {
				t.Fatal("database export did not resume", err)
			}
			after := snapshot(t, path)
			for name, digest := range before {
				if after[name] != digest {
					t.Fatal("resume changed an original database or backend identity")
				}
			}
		})
	}
}

func TestPrivatePKIDatabaseCommittedFileLoss(t *testing.T) {
	for _, name := range []string{"database/server.key", "database/server.pem", "identity.json"} {
		t.Run(name, func(t *testing.T) {
			path, config := fixture(t)
			config.DatabaseNames = []string{"database.internal"}
			if _, err := Initialize(t.Context(), path, config); err != nil {
				t.Fatal(err)
			}
			if os.Remove(filepath.Join(path, name)) != nil {
				t.Fatal("cannot remove synthetic identity fixture")
			}
			before := snapshot(t, path)
			if _, err := Initialize(t.Context(), path, config); !errors.Is(err, ErrState) || !reflect.DeepEqual(before, snapshot(t, path)) {
				t.Fatal("missing committed database key was recreated", err)
			}
		})
	}
}
