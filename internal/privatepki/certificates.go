//go:build linux || darwin

package privatepki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"time"
)

func newKey(console bool) ([]byte, error) {
	if console {
		// The existing console configuration parser accepts RSA PKCS#1 keys.
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data}), nil
}

func decodeBlock(data []byte, kind string) ([]byte, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != kind || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(data, []byte("-----BEGIN "+kind+"-----\n")) || bytes.Count(data, []byte("-----BEGIN ")) != 1 {
		return nil, ErrCertificate
	}
	return block.Bytes, nil
}

func readKey(data []byte, console bool) (crypto.Signer, error) {
	if console {
		der, err := decodeBlock(data, "RSA PRIVATE KEY")
		if err != nil {
			return nil, err
		}
		key, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil || key.N.BitLen() != 3072 || key.Validate() != nil {
			return nil, ErrCertificate
		}
		return key, nil
	}
	der, err := decodeBlock(data, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return nil, ErrCertificate
	}
	return key, nil
}

func template(b binding, role string) *x509.Certificate {
	t := &x509.Certificate{Subject: pkix.Name{CommonName: "OpenUEM " + b.Config.Name + " " + role + " " + b.Installation},
		NotBefore: b.CreatedAt.Add(-5 * time.Minute), NotAfter: b.CreatedAt.AddDate(1, 0, 0),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	switch role {
	case "authority":
		t.IsCA, t.MaxPathLenZero = true, true
		t.NotAfter = b.CreatedAt.AddDate(10, 0, 0)
		t.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	case "console":
		t.DNSNames = slices.Clone(b.Config.ConsoleNames)
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "broker":
		t.DNSNames = slices.Clone(b.Config.BrokerNames)
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "database":
		t.DNSNames = slices.Clone(b.Config.DatabaseNames)
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "gateway":
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	return t
}

func issue(b binding, role string, key crypto.Signer, authority *x509.Certificate, authorityKey crypto.Signer) ([]byte, error) {
	t := template(b, role)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil || serial.Sign() <= 0 {
		return nil, ErrCertificate
	}
	t.SerialNumber = serial
	if authority == nil {
		authority, authorityKey = t, key
	}
	der, err := x509.CreateCertificate(rand.Reader, t, authority, key.Public(), authorityKey)
	if err != nil {
		return nil, ErrCertificate
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func validateCertificate(b binding, role string, data []byte, key crypto.Signer, authority *x509.Certificate, now time.Time) (*x509.Certificate, error) {
	der, err := decodeBlock(data, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, ErrCertificate
	}
	want := template(b, role)
	publicKey, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil || !bytes.Equal(cert.RawSubjectPublicKeyInfo, publicKey) || cert.Subject.String() != want.Subject.String() ||
		!cert.NotBefore.Equal(want.NotBefore) || !cert.NotAfter.Equal(want.NotAfter) ||
		cert.KeyUsage != want.KeyUsage || !slices.Equal(cert.ExtKeyUsage, want.ExtKeyUsage) ||
		cert.IsCA != want.IsCA || cert.MaxPathLenZero != want.MaxPathLenZero || !cert.BasicConstraintsValid ||
		!slices.Equal(cert.DNSNames, want.DNSNames) || len(cert.IPAddresses)+len(cert.EmailAddresses)+len(cert.URIs) != 0 ||
		len(cert.UnknownExtKeyUsage)+len(cert.UnhandledCriticalExtensions) != 0 ||
		cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() > 159 || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, ErrCertificate
	}
	if authority == nil {
		authority = cert
	}
	if cert.CheckSignatureFrom(authority) != nil {
		return nil, ErrCertificate
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority)
	usage := x509.ExtKeyUsageServerAuth
	if role == "gateway" {
		usage = x509.ExtKeyUsageClientAuth
	}
	if role == "authority" {
		usage = x509.ExtKeyUsageAny
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return nil, ErrCertificate
	}
	return cert, nil
}
