package broker

import (
	"bytes"
	"context"
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
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/nats/enrollment/keyfile"
)

// This fixture requires actual distribution executables, including the previous
// initializer pinned to 938ea1a77eba4c9eb4517db629fc42ef2f8b96ad. The old renderer
// is therefore exercised independently of this package's migration helper.
func TestBrokerUpgradeDistributionProcess(t *testing.T) {
	current, legacy, server := os.Getenv("OPENUEM_UPGRADE_BINARY"), os.Getenv("OPENUEM_LEGACY_SETUP_BINARY"), os.Getenv("OPENUEM_BROKER_BINARY")
	if current == "" && legacy == "" && server == "" {
		t.Skip("requires the isolated broker upgrade distribution fixture")
	}
	if current == "" || legacy == "" || server == "" || os.Geteuid() == 0 {
		t.Fatal("all actual runtime binaries and an unprivileged account are required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	root := t.TempDir()
	ca, certificate, private := upgradeTLS(t)
	caPath, certPath, keyPath := filepath.Join(root, "ca.pem"), filepath.Join(root, "server.pem"), filepath.Join(root, "server.key")
	for path, data := range map[string][]byte{caPath: ca, certPath: certificate, keyPath: private} {
		if keyfile.Create(path, data) != nil {
			t.Fatal("cannot create synthetic TLS inputs")
		}
	}
	address := func() string {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal("cannot allocate private fixture address")
		}
		value := listener.Addr().String()
		listener.Close()
		return value
	}
	listen, websocket := address(), address()
	directory := filepath.Join(root, "broker")
	storage := filepath.Join(root, "jetstream")
	run := func(binary string, args ...string) []byte {
		t.Helper()
		output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		if err != nil {
			t.Fatal("actual broker setup or upgrade command failed")
		}
		return output
	}
	run(legacy, "individual-broker", "--directory", directory, "--name", "upgrade-fixture", "--listen", listen, "--websocket-listen", websocket,
		"--tls-cert", certPath, "--tls-key", keyPath, "--gateway-ca", caPath, "--store-directory", storage)
	before := upgradeFiles(t, directory)
	output := run(current, "individual-broker-upgrade", "--directory", directory, "--check")
	var plan UpgradePlan
	if json.Unmarshal(output, &plan) != nil || !plan.ChangeRequired {
		t.Fatal("actual old renderer was not recognized for upgrade")
	}
	if !reflect.DeepEqual(before, upgradeFiles(t, directory)) {
		t.Fatal("actual preview changed installed files")
	}
	connect := func(role string, failures chan error) (*nats.Conn, error) {
		seed, err := keyfile.Read(filepath.Join(directory, role+"-user.seed"), 512)
		if err != nil {
			return nil, ErrUpgrade
		}
		pair, err := nkeys.FromSeed(seed)
		clear(seed)
		if err != nil {
			return nil, ErrUpgrade
		}
		defer pair.Wipe()
		public, _ := pair.PublicKey()
		return nats.Connect("tls://"+listen, nats.Secure(&tls.Config{MinVersion: tls.VersionTLS12}), nats.RootCAs(caPath), nats.Nkey(public, pair.Sign), nats.NoReconnect(), nats.Timeout(time.Second),
			nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
				if failures != nil {
					select {
					case failures <- err:
					default:
					}
				}
			}))
	}
	start := func() func() {
		t.Helper()
		command := exec.CommandContext(ctx, server, "-c", filepath.Join(directory, "broker.json"))
		command.Stdout, command.Stderr = io.Discard, io.Discard
		if command.Start() != nil {
			t.Fatal("actual broker did not start")
		}
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		stopped := false
		stop := func() {
			t.Helper()
			if stopped {
				return
			}
			stopped = true
			_ = command.Process.Signal(syscall.SIGTERM)
			select {
			case err := <-done:
				if err != nil {
					t.Error("broker did not join a successful shutdown")
				}
			case <-time.After(5 * time.Second):
				_ = command.Process.Kill()
				<-done
				t.Error("broker did not stop before its deadline")
			}
		}
		t.Cleanup(stop)
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			connection, err := connect("provisioner", nil)
			if err == nil {
				connection.Close()
				return stop
			}
			select {
			case <-done:
				stopped = true
				t.Fatal("broker exited before authenticated TLS readiness")
			default:
			}
			time.Sleep(30 * time.Millisecond)
		}
		t.Fatal("broker did not reach authenticated TLS readiness")
		return stop
	}
	permission := func(allowed bool, subject string) {
		t.Helper()
		failures := make(chan error, 8)
		connection, err := connect("worker", failures)
		if err != nil {
			t.Fatal("retained worker key could not authenticate")
		}
		defer connection.Close()
		subscription, err := connection.SubscribeSync(subject)
		if err != nil || connection.FlushTimeout(time.Second) != nil {
			t.Fatal("worker subscription probe failed")
		}
		defer subscription.Unsubscribe()
		select {
		case err := <-failures:
			if allowed || !errors.Is(err, nats.ErrPermissionViolation) {
				t.Fatal("unexpected worker subscription decision")
			}
		case <-time.After(150 * time.Millisecond):
			if !allowed {
				t.Fatal("worker received an unconfigured subscription grant")
			}
		}
	}
	provisioner := func() (*nats.Conn, jetstream.JetStream) {
		t.Helper()
		connection, err := connect("provisioner", nil)
		if err != nil {
			t.Fatal("retained provisioning key rejected")
		}
		js, err := jetstream.New(connection)
		if err != nil {
			connection.Close()
			t.Fatal("JetStream API unavailable")
		}
		return connection, js
	}
	publish := func() {
		t.Helper()
		connection, err := connect("console", nil)
		if err != nil {
			t.Fatal("retained console key rejected")
		}
		defer connection.Close()
		js, err := jetstream.New(connection)
		if err != nil {
			t.Fatal("publisher JetStream API unavailable")
		}
		if _, err := js.Publish(ctx, "agent.upgrade.ping", []byte("synthetic retained command")); err != nil {
			t.Fatal("console command publication failed")
		}
	}
	stop := start()
	permission(false, "uem.v1.agent.*.request.hardware")
	connection, js := provisioner()
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: "AGENTS_STREAM", Subjects: []string{"agent.>"}, Storage: jetstream.FileStorage}); err != nil {
		t.Fatal("original stream could not be created")
	}
	if _, err := js.CreateConsumer(ctx, "AGENTS_STREAM", jetstream.ConsumerConfig{Durable: "upgrade-fixture", AckPolicy: jetstream.AckExplicitPolicy, FilterSubject: "agent.upgrade.>"}); err != nil {
		t.Fatal("original durable consumer could not be created")
	}
	publish()
	connection.Close()
	stop()
	result := run(current, "individual-broker-upgrade", "--directory", directory, "--expected-sha256", plan.Before)
	var completed UpgradePlan
	if json.Unmarshal(result, &completed) != nil || completed.ChangeRequired || completed.Before != plan.Before || completed.After != plan.After {
		t.Fatal("actual upgrade did not report retained completion")
	}
	after := upgradeFiles(t, directory)
	retry := run(current, "individual-broker-upgrade", "--directory", directory, "--expected-sha256", plan.Before)
	if !bytes.Equal(result, retry) || !reflect.DeepEqual(after, upgradeFiles(t, directory)) {
		t.Fatal("actual retry changed completed upgrade")
	}
	for _, name := range serviceSeeds {
		if before[name] != after[name] {
			t.Fatal("actual upgrade rotated a service identity")
		}
		data, _ := os.ReadFile(filepath.Join(directory, name))
		if bytes.Contains(output, data) || bytes.Contains(result, data) {
			t.Fatal("actual command output leaked a service seed")
		}
		clear(data)
	}
	stop = start()
	for _, operation := range []string{"hardware", "recovery", "rotation"} {
		permission(true, "uem.v1.agent.*.request."+operation)
	}
	permission(false, "uem.v1.agent.*.request.>")
	connection, js = provisioner()
	stream, err := js.Stream(ctx, "AGENTS_STREAM")
	if err != nil {
		t.Fatal("retained command stream is missing")
	}
	info, err := stream.Info(ctx)
	if err != nil || info.State.Msgs != 1 || info.State.LastSeq != 1 {
		t.Fatal("upgrade lost the retained command message")
	}
	consumer, err := js.Consumer(ctx, "AGENTS_STREAM", "upgrade-fixture")
	if err != nil {
		t.Fatal("upgrade lost the durable consumer")
	}
	state, err := consumer.Info(ctx)
	if err != nil || state.NumPending != 1 {
		t.Fatal("upgrade lost pending command state")
	}
	publish()
	state, err = consumer.Info(ctx)
	if err != nil || state.NumPending != 2 {
		t.Fatal("retained consumer did not receive subsequent commands")
	}
	connection.Close()
	stop()
}

func upgradeTLS(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic upgrade CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
}
