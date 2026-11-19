package certmon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/zap"
)

// selfSigned returns a certificate valid until notAfter, as a TLS certificate
// and as PEM.
func selfSigned(t *testing.T, notAfter time.Time) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "internal.test"},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"internal.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func sameSecond(a, b time.Time) bool { return a.Unix() == b.Unix() }

func TestFileNotAfterTakesTheEarliestInABundle(t *testing.T) {
	late := time.Now().Add(900 * 24 * time.Hour)
	soon := time.Now().Add(12 * 24 * time.Hour)
	_, latePEM := selfSigned(t, late)
	_, soonPEM := selfSigned(t, soon)
	path := filepath.Join(t.TempDir(), "bundle.crt")
	if err := os.WriteFile(path, append(latePEM, soonPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := fileNotAfter(path)
	if err != nil {
		t.Fatal(err)
	}
	if !sameSecond(got, soon) {
		t.Fatalf("got %v, want the earlier certificate's %v", got, soon)
	}
	if _, err := fileNotAfter(filepath.Join(t.TempDir(), "absent.crt")); err == nil {
		t.Fatal("a missing file must be an error, not a zero date")
	}
}

// serveTLS answers TLS handshakes with cert until the test ends.
func serveTLS(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// The certificate this monitor most needs to report is one a verifying client
// would refuse to talk to. Reading it must still work.
func TestTLSNotAfterReadsAnExpiredCertificate(t *testing.T) {
	expired := time.Now().Add(-3 * 24 * time.Hour)
	cert, _ := selfSigned(t, expired)
	got, err := tlsNotAfter(context.Background(), serveTLS(t, cert))
	if err != nil {
		t.Fatalf("an expired certificate could not be read: %v", err)
	}
	if !sameSecond(got, expired) {
		t.Fatalf("got %v, want %v", got, expired)
	}
}

// servePostgres speaks just enough Postgres: read the 8-byte SSLRequest, answer
// with `answer`, and — if that was 'S' — do a TLS handshake.
func servePostgres(t *testing.T, cert tls.Certificate, answer byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				req := make([]byte, 8)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				// length 8, code 80877103 = 0x04D2162F
				if req[3] != 8 || req[4] != 0x04 || req[5] != 0xD2 || req[6] != 0x16 || req[7] != 0x2F {
					return
				}
				if _, err := c.Write([]byte{answer}); err != nil || answer != 'S' {
					return
				}
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
				_ = tc.Handshake()
				_, _ = io.Copy(io.Discard, tc)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestPostgresNotAfterNegotiatesTLSTheWayAClientDoes(t *testing.T) {
	soon := time.Now().Add(9 * 24 * time.Hour)
	cert, _ := selfSigned(t, soon)
	got, err := postgresNotAfter(context.Background(), servePostgres(t, cert, 'S'))
	if err != nil {
		t.Fatal(err)
	}
	if !sameSecond(got, soon) {
		t.Fatalf("got %v, want %v", got, soon)
	}
}

func TestPostgresWithoutTLSIsAnErrorNotADate(t *testing.T) {
	cert, _ := selfSigned(t, time.Now().Add(time.Hour))
	if _, err := postgresNotAfter(context.Background(), servePostgres(t, cert, 'N')); err == nil {
		t.Fatal("a server that refuses TLS has no certificate to report")
	}
}

func TestCertsSkipsWhatItCannotReach(t *testing.T) {
	soon := time.Now().Add(20 * 24 * time.Hour)
	cert, pemBytes := selfSigned(t, soon)
	ca := filepath.Join(t.TempDir(), "root.crt")
	if err := os.WriteFile(ca, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	// A port nothing listens on.
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()

	src := InternalSource{
		PostgresAddr: servePostgres(t, cert, 'S'),
		TLSAddrs:     map[string]string{"event database (ClickHouse) server certificate": deadAddr},
		CAFiles:      map[string]string{"internal root CA": ca, "missing": filepath.Join(t.TempDir(), "no.crt")},
	}
	got := src.Certs(context.Background())
	if len(got) != 2 {
		t.Fatalf("got %d certificates %+v, want the CA file and Postgres only", len(got), got)
	}
	for _, c := range got {
		if c.ExpiresAt != soon.Unix() {
			t.Errorf("%s: expires_at %d, want %d", c.Domain, c.ExpiresAt, soon.Unix())
		}
	}
}

func TestInternalSourceFromEnv(t *testing.T) {
	t.Setenv("SENTINEL_DB_URL", "postgres://sentinel_cp:pw@postgres:5432/sentinel?sslmode=verify-full&sslrootcert=/etc/sentinel/pki/root.crt")
	t.Setenv("SENTINEL_CLICKHOUSE_URL", "https://clickhouse:8443")
	t.Setenv("SENTINEL_CLICKHOUSE_CA_FILE", "/etc/sentinel/pki/root.crt")
	s := InternalSourceFromEnv()
	if s.PostgresAddr != "postgres:5432" {
		t.Errorf("PostgresAddr = %q", s.PostgresAddr)
	}
	if got := s.TLSAddrs["event database (ClickHouse) server certificate"]; got != "clickhouse:8443" {
		t.Errorf("clickhouse addr = %q", got)
	}
	if len(s.CAFiles) != 1 || s.CAFiles["internal root CA"] != "/etc/sentinel/pki/root.crt" {
		t.Errorf("CAFiles = %v, want the one root (the same file named twice is one certificate)", s.CAFiles)
	}

	// No TLS configured: nothing to watch, and no dial of a plaintext port.
	t.Setenv("SENTINEL_DB_URL", "postgres://sentinel:pw@localhost/sentinel?sslmode=disable")
	t.Setenv("SENTINEL_CLICKHOUSE_URL", "http://clickhouse:8123")
	t.Setenv("SENTINEL_CLICKHOUSE_CA_FILE", "")
	s = InternalSourceFromEnv()
	if s.PostgresAddr != "" || len(s.TLSAddrs) != 0 || len(s.CAFiles) != 0 {
		t.Errorf("plaintext deployment produced a source: %+v", s)
	}
}

type raised struct {
	domain string
	days   int64
	sev    string
}

func monitorWithRecorder(dataPlaneURL string) (*Monitor, *[]raised) {
	m := New(nil, dataPlaneURL, "", zap.NewNop())
	var got []raised
	m.raise = func(c certEntry, days int64, sev string) { got = append(got, raised{c.Domain, days, sev}) }
	return m, &got
}

func TestAnInternalCertificateNearExpiryRaisesOncePerLevel(t *testing.T) {
	m, got := monitorWithRecorder("http://127.0.0.1:1")
	now := time.Now()
	pg := certEntry{Domain: "database (Postgres) server certificate", Name: "internal",
		ExpiresAt: now.Add(10*24*time.Hour + time.Hour).Unix()}

	m.evaluate([]certEntry{pg}, now)
	m.evaluate([]certEntry{pg}, now) // same level: no second alert
	if len(*got) != 1 || (*got)[0].sev != "high" || (*got)[0].days != 10 {
		t.Fatalf("alerts = %+v, want one `high` at 10 days", *got)
	}
	m.evaluate([]certEntry{pg}, now.Add(5*24*time.Hour)) // now 5 days out
	if len(*got) != 2 || (*got)[1].sev != "critical" {
		t.Fatalf("alerts = %+v, want an escalation to critical", *got)
	}
}

// The data plane being down used to end the tick. The certificates that do not
// come from it must still be checked.
func TestInternalCertificatesAreCheckedWhenTheDataPlaneIsDown(t *testing.T) {
	m, got := monitorWithRecorder("http://127.0.0.1:1") // nothing listens on port 1
	m.SetInternalCerts(func(context.Context) []certEntry {
		return []certEntry{{Domain: "internal root CA", Name: "internal",
			ExpiresAt: time.Now().Add(3 * 24 * time.Hour).Unix()}}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	site, internal, err := m.tick(ctx)
	if err == nil {
		t.Fatal("the data-plane failure must still be reported")
	}
	if site != 0 || internal != 1 {
		t.Fatalf("checked %d site / %d internal, want 0 / 1", site, internal)
	}
	if len(*got) != 1 || (*got)[0].domain != "internal root CA" || (*got)[0].sev != "critical" {
		t.Fatalf("alerts = %+v, want a critical alert for the root CA", *got)
	}
}
