//go:build linux || darwin

package privatepki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func administratorRoots(t *testing.T, path string) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	load := func(name string) *x509.Certificate {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(path, name))
		if err != nil {
			t.Fatal(err)
		}
		der, err := decodeBlock(data, "CERTIFICATE")
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	backend, administrator := load("trust/backend-ca.pem"), load("trust/administrator-ca.pem")
	if bytes.Equal(backend.RawSubjectPublicKeyInfo, administrator.RawSubjectPublicKeyInfo) ||
		!administrator.IsCA || !administrator.MaxPathLenZero || administrator.CheckSignatureFrom(administrator) != nil ||
		administrator.CheckSignatureFrom(backend) == nil || backend.CheckSignatureFrom(administrator) == nil {
		t.Fatal("administrator authority is not an independent root")
	}
	if !bytes.Equal(administrator.Raw, load("administrator-authority/ca.pem").Raw) {
		t.Fatal("administrator trust does not match its retained authority")
	}
	return backend, administrator
}

func TestPrivatePKIAdministratorAuthorityAndSeparateTLSAdmission(t *testing.T) {
	path, config := fixture(t)
	config.AdministratorAuthority = true
	config.DatabaseNames = []string{"database.internal"}
	manifest, err := Initialize(t.Context(), path, config)
	if err != nil || len(manifest.Files) != 17 {
		t.Fatal("administrator authority export failed", err)
	}
	backend, administrator := administratorRoots(t, path)
	before := snapshot(t, path)
	if _, err := Initialize(t.Context(), path, config); err != nil || !reflect.DeepEqual(before, snapshot(t, path)) {
		t.Fatal("administrator authority retry changed retained identities", err)
	}
	data, err := os.ReadFile(filepath.Join(path, "administrator-authority/ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	issuer, err := readKey(data, false)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Only this test issues a client certificate. Initialization exports the CA;
	// account binding, enrollment and revocation remain separate operations.
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic administrator"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, administrator, key.Public(), issuer)
	if err != nil {
		t.Fatal(err)
	}
	clientIdentity := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	serverIdentity, err := tls.LoadX509KeyPair(filepath.Join(path, "console/server.pem"), filepath.Join(path, "console/server.key"))
	if err != nil {
		t.Fatal(err)
	}
	gatewayIdentity, err := tls.LoadX509KeyPair(filepath.Join(path, "gateway/client.pem"), filepath.Join(path, "gateway/client.key"))
	if err != nil {
		t.Fatal(err)
	}
	backendRoots, adminRoots := x509.NewCertPool(), x509.NewCertPool()
	backendRoots.AddCert(backend)
	adminRoots.AddCert(administrator)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverIdentity}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: adminRoots, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	for name, identity := range map[string]tls.Certificate{"administrator": clientIdentity, "backend gateway": gatewayIdentity} {
		t.Run(name, func(t *testing.T) {
			transport := &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{identity}, RootCAs: backendRoots, ServerName: "console.internal", MinVersion: tls.VersionTLS12}}
			defer transport.CloseIdleConnections()
			response, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get(server.URL)
			if err == nil {
				response.Body.Close()
			}
			if name == "administrator" && (err != nil || response.StatusCode != http.StatusNoContent) || name != "administrator" && err == nil {
				t.Fatal("administrator TLS admission crossed the authority boundary")
			}
		})
	}
	assertTLS(t, path)
}

func TestPrivatePKIAdministratorAuthorityCompatibilityAndInterruptedExports(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		path, config := fixture(t)
		config.AdministratorAuthority = enabled
		if _, err := Initialize(t.Context(), path, config); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t, path)
		changed := config
		changed.AdministratorAuthority = !enabled
		if _, err := Initialize(t.Context(), path, changed); !errors.Is(err, ErrState) || !reflect.DeepEqual(before, snapshot(t, path)) {
			t.Fatal("administrator authority mode changed retained PKI", err)
		}
		if !enabled {
			data, err := os.ReadFile(filepath.Join(path, "configuration.json"))
			if err != nil || bytes.Contains(data, []byte("administrator_authority")) {
				t.Fatal("existing PKI configuration encoding changed")
			}
		}
	}
	for _, point := range []string{"administrator-authority/ca.key", "administrator-authority/ca.pem", "trust/administrator-ca.pem"} {
		t.Run(point, func(t *testing.T) {
			path, config := fixture(t)
			config.AdministratorAuthority = true
			d, err := openDirectory(path)
			if err != nil {
				t.Fatal(err)
			}
			defer d.close()
			interrupted := errors.New("synthetic administrator export interruption")
			_, err = initialize(t.Context(), d, config, time.Now().UTC().Truncate(time.Second), func(name string) error {
				if name == point {
					return interrupted
				}
				return nil
			})
			if !errors.Is(err, interrupted) {
				t.Fatal("administrator export interruption was not reached", err)
			}
			before := snapshot(t, path)
			if _, err := initialize(t.Context(), d, config, time.Now().UTC().Truncate(time.Second), nil); err != nil {
				t.Fatal("administrator export did not resume", err)
			}
			for name, fingerprint := range before {
				if snapshot(t, path)[name] != fingerprint {
					t.Fatal("resume replaced retained administrator or backend material")
				}
			}
			administratorRoots(t, path)
		})
	}
}

func TestPrivatePKIAdministratorAuthorityRejectsLossAndBackendCrossSigning(t *testing.T) {
	for _, damage := range []string{"administrator-authority/ca.key", "administrator-authority/ca.pem", "trust/administrator-ca.pem", "cross-signed authority"} {
		t.Run(damage, func(t *testing.T) {
			path, config := fixture(t)
			config.AdministratorAuthority = true
			if _, err := Initialize(t.Context(), path, config); err != nil {
				t.Fatal(err)
			}
			if damage != "cross-signed authority" {
				if err := os.Remove(filepath.Join(path, damage)); err != nil {
					t.Fatal(err)
				}
			} else {
				backend, administrator := administratorRoots(t, path)
				data, err := os.ReadFile(filepath.Join(path, "identity.json"))
				if err != nil {
					t.Fatal(err)
				}
				defer clear(data)
				var retained identity
				if err := json.Unmarshal(data, &retained); err != nil {
					t.Fatal(err)
				}
				defer retained.clear()
				key, err := readKey(retained.Files["authority/ca.key"], false)
				if err != nil {
					t.Fatal(err)
				}
				der, err := x509.CreateCertificate(rand.Reader, administrator, backend, administrator.PublicKey, key)
				if err != nil {
					t.Fatal(err)
				}
				retained.Files["administrator-authority/ca.pem"] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
				encoded, err := json.Marshal(retained)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(encoded)
				if err := os.WriteFile(filepath.Join(path, "identity.json"), encoded, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := snapshot(t, path)
			if _, err := Initialize(t.Context(), path, config); err == nil || !reflect.DeepEqual(before, snapshot(t, path)) {
				t.Fatal("damaged administrator authority was accepted or replaced")
			}
		})
	}
}
