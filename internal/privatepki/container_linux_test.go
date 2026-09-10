package privatepki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPrivatePKIContainerGateway(t *testing.T) {
	initializer := os.Getenv("OPENUEM_PRIVATE_PKI_TEST_BINARY")
	if initializer == "" {
		t.Skip("requires the isolated private PKI smoke container")
	}
	gatewayBinary := os.Getenv("OPENUEM_GATEWAY_TEST_BINARY")
	if gatewayBinary == "" {
		t.Fatal("the actual gateway executable is required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	path, _ := fixture(t)
	run := func() error {
		command := exec.CommandContext(ctx, initializer, "private-pki", "--directory", path, "--database-dns", "database.internal", "--administrator-authority")
		output, err := command.CombinedOutput()
		if bytes.Contains(output, []byte("PRIVATE KEY")) {
			t.Fatal("initializer printed private material")
		}
		return err
	}
	if err := run(); err != nil {
		t.Fatal("actual initializer failed", err)
	}
	administratorRoots(t, path)
	if _, err := tls.LoadX509KeyPair(filepath.Join(path, "database/server.pem"), filepath.Join(path, "database/server.key")); err != nil {
		t.Fatal("actual initializer did not export a usable separate database identity")
	}
	first := snapshot(t, path)
	if err := run(); err != nil {
		t.Fatal("actual initializer retry failed", err)
	}
	for name, digest := range snapshot(t, path) {
		if first[name] != digest {
			t.Fatal("actual retry changed identity", name)
		}
	}
	serverIdentity, err := tls.LoadX509KeyPair(filepath.Join(path, "console/server.pem"), filepath.Join(path, "console/server.key"))
	if err != nil {
		t.Fatal(err)
	}
	gatewayPEM, err := os.ReadFile(filepath.Join(path, "console/gateway-leaves.pem"))
	if err != nil {
		t.Fatal(err)
	}
	gatewayDER, err := decodeBlock(gatewayPEM, "CERTIFICATE")
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	clientRoots.AppendCertsFromPEM(gatewayPEM)
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 1 || !bytes.Equal(r.TLS.PeerCertificates[0].Raw, gatewayDER) {
			t.Error("wrong gateway reached the private backend")
		}
		_, _ = io.WriteString(w, "private-ready")
	}))
	backend.Config.ErrorLog = log.New(io.Discard, "", 0)
	backend.TLS = &tls.Config{Certificates: []tls.Certificate{serverIdentity}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots, MinVersion: tls.VersionTLS12}
	backend.StartTLS()
	defer backend.Close()
	_, backendPort, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	backendURL := "https://console.internal:" + backendPort
	publicCert, publicKey, publicRoots := fixturePublicTLS(t, filepath.Dir(path))
	args := []string{"--listen", "127.0.0.1:18443", "--public-origin", "https://uem.example.test",
		"--tls-cert", publicCert, "--tls-key", publicKey,
		"--gateway-cert", filepath.Join(path, "gateway/client.pem"), "--gateway-key", filepath.Join(path, "gateway/client.key"),
		"--backend-ca", filepath.Join(path, "gateway/backend-ca.pem"),
		"--apple-url", backendURL, "--console-url", backendURL, "--auth-url", backendURL, "--admin-networks", "10.42.0.0/16"}
	command := exec.CommandContext(ctx, gatewayBinary, args...)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	joined := false
	defer func() {
		if !joined {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: publicRoots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:18443")
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for {
		response, err := client.Get("https://uem.example.test/mdm/apple/enroll/" + strings.Repeat("a", 43))
		if err == nil {
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusOK || readErr != nil || string(body) != "private-ready" {
				t.Fatal("actual gateway could not use generated CA-issued identity", response.StatusCode, readErr)
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("actual gateway did not start", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	response, err := client.Get("https://uem.example.test/login")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("public source reached administration", response.StatusCode)
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal("actual gateway did not stop cleanly", err)
	}
	joined = true
	if bytes.Contains(output.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatal("gateway printed private material")
	}
	if err := os.Remove(filepath.Join(path, "gateway/client.key")); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil {
		t.Fatal("actual initializer replaced a missing committed key")
	}
	if _, err := os.Stat(filepath.Join(path, "gateway/client.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed retry recreated the missing key", err)
	}
	t.Log("actual initializer and gateway: retained private PKI, CA-issued client selection, pinned TLS, public admin denial and shutdown passed")
}

func fixturePublicTLS(t *testing.T, path string) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"uem.example.test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath, keyPath := filepath.Join(path, "public.pem"), filepath.Join(path, "public.key")
	if err := os.WriteFile(certificatePath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	return certificatePath, keyPath, roots
}
