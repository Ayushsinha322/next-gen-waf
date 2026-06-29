package certval

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// genCert mints a self-signed ECDSA P-256 cert+key for testing.
func genCert(t *testing.T, notBefore, notAfter time.Time, dns []string, ips []net.IP) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-cert"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dns,
		IPAddresses:           ips,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestValidate_Valid(t *testing.T) {
	cert, key := genCert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour),
		[]string{"mgmt.local"}, []net.IP{net.ParseIP("172.16.21.71")})
	res, err := Validate(cert, key, "", "172.16.21.71")
	if err != nil {
		t.Fatalf("expected valid, got error: %v", err)
	}
	if res.KeyType != "ECDSA P-256" {
		t.Errorf("key type = %q, want ECDSA P-256", res.KeyType)
	}
	if len(res.SANs) != 2 {
		t.Errorf("SANs = %v, want 2", res.SANs)
	}
	if !res.SelfSigned {
		t.Error("expected self-signed = true")
	}
	if res.FingerprintSHA256 == "" || len(res.FingerprintSHA256) != 64 {
		t.Errorf("fingerprint = %q, want 64 hex chars", res.FingerprintSHA256)
	}
	// IP SAN matches expectedHost → no hostname-mismatch warning.
	for _, w := range res.Warnings {
		if strings.Contains(w, "not valid for") {
			t.Errorf("unexpected hostname warning: %s", w)
		}
	}
}

func TestValidate_KeyMismatch(t *testing.T) {
	cert, _ := genCert(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []string{"a.local"}, nil)
	_, key2 := genCert(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []string{"b.local"}, nil)
	if _, err := Validate(cert, key2, "", ""); err == nil {
		t.Fatal("expected key-mismatch error, got nil")
	}
}

func TestValidate_Expired(t *testing.T) {
	cert, key := genCert(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), []string{"a.local"}, nil)
	if _, err := Validate(cert, key, "", ""); err == nil {
		t.Fatal("expected expired error, got nil")
	}
}

func TestValidate_NotYetValid(t *testing.T) {
	cert, key := genCert(t, time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour), []string{"a.local"}, nil)
	if _, err := Validate(cert, key, "", ""); err == nil {
		t.Fatal("expected not-yet-valid error, got nil")
	}
}

func TestValidate_NoSAN(t *testing.T) {
	cert, key := genCert(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil, nil)
	if _, err := Validate(cert, key, "", ""); err == nil {
		t.Fatal("expected no-SAN error, got nil")
	}
}

func TestValidate_HostnameWarning(t *testing.T) {
	cert, key := genCert(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), []string{"other.local"}, nil)
	res, err := Validate(cert, key, "", "wanted.local")
	if err != nil {
		t.Fatalf("expected valid (warning only), got error: %v", err)
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "wanted.local") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected hostname-mismatch warning, got %v", res.Warnings)
	}
}

func TestValidate_GarbageRejected(t *testing.T) {
	if _, err := Validate("not a cert", "not a key", "", ""); err == nil {
		t.Fatal("expected error for garbage input, got nil")
	}
}
