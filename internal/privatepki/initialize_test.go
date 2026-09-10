//go:build linux || darwin

package privatepki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/open-uem/utils"
)

func fixture(t *testing.T) (string, Config) {
	t.Helper()
	return filepath.Join(t.TempDir(), "private-pki"), Config{Version: 1, Name: "synthetic", ConsoleNames: []string{"console.internal"}, BrokerNames: []string{"nats.internal"}}
}

func snapshot(t *testing.T, path string) map[string][32]byte {
	t.Helper()
	result := map[string][32]byte{}
	err := filepath.WalkDir(path, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		defer clear(data)
		result[path] = sha256.Sum256(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPrivatePKIProducesUsableSeparatedIdentitiesAndExactRetry(t *testing.T) {
	path, c := fixture(t)
	manifest, err := Initialize(t.Context(), path, c)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != 1 || len(manifest.Files) != len(artifacts) || !manifest.NotAfter.After(time.Now()) {
		t.Fatal("incomplete readiness manifest")
	}
	for name, expected := range manifest.Files {
		data, err := os.ReadFile(filepath.Join(path, name))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		clear(data)
		if hex.EncodeToString(digest[:]) != expected {
			t.Fatal("manifest does not match the published file", name)
		}
	}
	before := snapshot(t, path)
	retry, err := Initialize(t.Context(), path, c)
	if err != nil || !reflect.DeepEqual(manifest, retry) || !reflect.DeepEqual(before, snapshot(t, path)) {
		t.Fatal("retry replaced retained identity", err)
	}
	if _, err := utils.ReadPEMPrivateKey(filepath.Join(path, "console/server.key")); err != nil {
		t.Fatal("existing console parser rejects generated private key", err)
	}
	assertTLS(t, path)
}

func assertTLS(t *testing.T, path string) {
	t.Helper()
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(path, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	backendRoots := x509.NewCertPool()
	if !backendRoots.AppendCertsFromPEM(read("trust/backend-ca.pem")) {
		t.Fatal("missing backend trust")
	}
	gatewayRoots := x509.NewCertPool()
	if !gatewayRoots.AppendCertsFromPEM(read("broker/gateway-leaves.pem")) {
		t.Fatal("missing exact gateway leaf trust")
	}
	gateway, err := tls.LoadX509KeyPair(filepath.Join(path, "gateway/client.pem"), filepath.Join(path, "gateway/client.key"))
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"console", "broker"} {
		serverIdentity, err := tls.LoadX509KeyPair(filepath.Join(path, role, "server.pem"), filepath.Join(path, role, "server.key"))
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.TLS.PeerCertificates) != 1 || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, gateway.Certificate[0]) {
				t.Error("wrong client reached private backend")
			}
			_, _ = io.WriteString(w, "ready")
		}))
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.TLS = &tls.Config{Certificates: []tls.Certificate{serverIdentity}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: gatewayRoots, MinVersion: tls.VersionTLS12}
		server.StartTLS()
		defer server.Close()
		name := "console.internal"
		if role == "broker" {
			name = "nats.internal"
		}
		request := func(clientIdentity []tls.Certificate, hostname string) error {
			configuration := &tls.Config{RootCAs: backendRoots, ServerName: hostname, Certificates: clientIdentity, MinVersion: tls.VersionTLS12}
			if len(clientIdentity) == 1 {
				// Explicit gateway selection ignores issuer hints from an exact
				// leaf trust pool; it still checks signature/version compatibility.
				configuration.GetClientCertificate = func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					selection := *request
					selection.AcceptableCAs = nil
					if err := selection.SupportsCertificate(&clientIdentity[0]); err != nil {
						return nil, err
					}
					return &clientIdentity[0], nil
				}
			}
			transport := &http.Transport{TLSClientConfig: configuration}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: time.Second}
			response, err := client.Get(server.URL)
			if err == nil {
				response.Body.Close()
				if response.StatusCode != http.StatusOK {
					return errors.New("private response failed")
				}
			}
			return err
		}
		if err := request([]tls.Certificate{gateway}, name); err != nil {
			t.Fatal("gateway could not authenticate to generated backend", role, err)
		}
		if err := request(nil, name); err == nil {
			t.Fatal("direct unauthenticated backend request succeeded")
		}
		if err := request([]tls.Certificate{serverIdentity}, name); err == nil {
			t.Fatal("server identity was accepted as a gateway")
		}
		if err := request([]tls.Certificate{gateway}, "wrong.internal"); err == nil {
			t.Fatal("wrong backend hostname was accepted")
		}
	}
}

func TestPrivatePKIRetainsIdentityAcrossInterruptedExport(t *testing.T) {
	path, c := fixture(t)
	d, err := openDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	interrupted := errors.New("synthetic write interruption")
	_, err = initialize(t.Context(), d, c, time.Now().UTC().Truncate(time.Second), func(name string) error {
		if name == "console/server.pem" {
			return interrupted
		}
		return nil
	})
	d.close()
	if !errors.Is(err, interrupted) {
		t.Fatal("did not stop at the injected boundary", err)
	}
	if _, err := os.Stat(filepath.Join(path, "manifest.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial export was marked ready", err)
	}
	retained := snapshot(t, path)
	if _, err := Initialize(t.Context(), path, c); err != nil {
		t.Fatal("valid interrupted prefix could not resume", err)
	}
	after := snapshot(t, path)
	for name, digest := range retained {
		if after[name] != digest {
			t.Fatal("restart replaced original identity", name)
		}
	}
	// Losing the last readiness marker and an exported suffix still retains the
	// original certificates and private keys from the durable identity record.
	complete := snapshot(t, path)
	for _, name := range append([]string{"manifest.json"}, artifacts[4:]...) {
		if err := os.Remove(filepath.Join(path, name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Initialize(t.Context(), path, c); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(complete, snapshot(t, path)) {
		t.Fatal("suffix recovery generated replacement keys or certificates")
	}
}

func TestPrivatePKIRefusesIdentityLossAndUnrecognizedData(t *testing.T) {
	for _, damage := range []string{"root key", "service key", "identity record", "binding", "changed configuration", "malformed manifest", "modified leaf", "foreign file", "symlink", "permissions"} {
		t.Run(damage, func(t *testing.T) {
			path, c := fixture(t)
			if _, err := Initialize(t.Context(), path, c); err != nil {
				t.Fatal(err)
			}
			var err error
			switch damage {
			case "root key":
				err = os.Remove(filepath.Join(path, "authority/ca.key"))
			case "service key":
				err = os.Remove(filepath.Join(path, "gateway/client.key"))
			case "identity record":
				err = os.Remove(filepath.Join(path, "identity.json"))
			case "binding":
				err = os.Remove(filepath.Join(path, "configuration.json"))
			case "changed configuration":
				c.ConsoleNames = []string{"other.internal"}
			case "malformed manifest":
				err = os.WriteFile(filepath.Join(path, "manifest.json"), []byte(`{"version":1`), 0600)
			case "modified leaf":
				data, _ := os.ReadFile(filepath.Join(path, "broker/server.pem"))
				err = os.WriteFile(filepath.Join(path, "gateway/client.pem"), data, 0600)
			case "foreign file":
				err = os.WriteFile(filepath.Join(path, "operator-note"), []byte("keep"), 0600)
			case "symlink":
				err = os.Symlink("../gateway/client.key", filepath.Join(path, "console/link"))
			case "permissions":
				err = os.Chmod(filepath.Join(path, "gateway/client.key"), 0644)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, path)
			if _, err := Initialize(t.Context(), path, c); err == nil {
				t.Fatal("damaged state accepted")
			}
			if !reflect.DeepEqual(before, snapshot(t, path)) {
				t.Fatal("failed verification changed retained data")
			}
		})
	}
}

func TestPrivatePKIRejectsCompetingWriterAndRootReplacement(t *testing.T) {
	path, c := fixture(t)
	d, err := openDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	if _, err := Initialize(t.Context(), path, c); !errors.Is(err, ErrLocked) {
		t.Fatal("competing initializer acquired lease", err)
	}
	if err := os.Rename(path, path+"-retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := initialize(t.Context(), d, c, time.Now().UTC(), nil); !errors.Is(err, ErrState) {
		t.Fatal("replaced root accepted", err)
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatal("replacement root was mutated", err)
	}
}

func TestPrivatePKICancellationExpiryAndInvalidConfiguration(t *testing.T) {
	path, c := fixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Initialize(ctx, path, c); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled setup created state", err)
	}
	for _, name := range []string{"localhost", "*.internal", "127.0.0.1", "console.internal:443", "CONSOLE.internal", "../console"} {
		bad := c
		bad.ConsoleNames = []string{name}
		if _, err := Initialize(t.Context(), path, bad); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid DNS configuration accepted", name, err)
		}
	}
	if _, err := Initialize(t.Context(), path, c); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, path)
	d, err := openDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	if _, err := initialize(t.Context(), d, c, time.Now().AddDate(2, 0, 0), nil); !errors.Is(err, ErrCertificate) {
		t.Fatal("expired private identity was silently renewed", err)
	}
	if !reflect.DeepEqual(before, snapshot(t, path)) {
		t.Fatal("expiry check replaced an identity")
	}
	// Duplicate or extra binding fields must not select an alternative config.
	data, err := os.ReadFile(filepath.Join(path, "configuration.json"))
	if err != nil {
		t.Fatal(err)
	}
	var b binding
	if json.Unmarshal(data, &b) != nil {
		t.Fatal("invalid original binding")
	}
	data = append([]byte(`{"installation":"ambiguous",`), data[1:]...)
	if err := os.WriteFile(filepath.Join(path, "configuration.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := initialize(t.Context(), d, c, time.Now(), nil); !errors.Is(err, ErrState) {
		t.Fatal("ambiguous binding accepted", err)
	}
}
