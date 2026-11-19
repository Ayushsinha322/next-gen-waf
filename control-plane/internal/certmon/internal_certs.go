package certmon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// The deployment's own certificates.
//
// The data plane's inventory — what this monitor read until now — is the
// certificates it SERVES: site certificates. It says nothing about the ones the
// deployment runs on: the internal root CA, the Postgres server certificate and
// the ClickHouse server certificate the installer mints (825 days). Those
// expire with no notice at all, and when the Postgres one does, every control
// plane node fails verify-full at once and the cluster stops — on a date that
// was known the day it was installed.
//
// The control plane can read all three without being handed a private key or a
// new mount: the CA files it already verifies against, and the certificate each
// server presents when it is dialled.

// InternalSource lists where the deployment's own certificates can be read.
type InternalSource struct {
	// PostgresAddr is host:port of a Postgres server that offers TLS, or "".
	PostgresAddr string
	// TLSAddrs are plain TLS endpoints, label → host:port (ClickHouse HTTPS).
	TLSAddrs map[string]string
	// CAFiles are PEM certificate files, label → path.
	CAFiles map[string]string
}

// InternalSourceFromEnv derives the source from the settings the control plane
// already runs with, so there is nothing new to configure — or to forget.
func InternalSourceFromEnv() InternalSource {
	s := InternalSource{TLSAddrs: map[string]string{}, CAFiles: map[string]string{}}

	if u, err := url.Parse(strings.TrimSpace(os.Getenv("SENTINEL_DB_URL"))); err == nil && u.Host != "" {
		q := u.Query()
		if mode := q.Get("sslmode"); mode != "disable" && mode != "" {
			s.PostgresAddr = hostPort(u, "5432")
		}
		if ca := q.Get("sslrootcert"); ca != "" {
			s.CAFiles["internal root CA"] = ca
		}
	}
	if u, err := url.Parse(strings.TrimSpace(os.Getenv("SENTINEL_CLICKHOUSE_URL"))); err == nil && u.Scheme == "https" && u.Host != "" {
		s.TLSAddrs["event database (ClickHouse) server certificate"] = hostPort(u, "443")
	}
	if ca := strings.TrimSpace(os.Getenv("SENTINEL_CLICKHOUSE_CA_FILE")); ca != "" && !hasValue(s.CAFiles, ca) {
		s.CAFiles["event database CA"] = ca
	}
	return s
}

func hostPort(u *url.URL, defaultPort string) string {
	if u.Port() != "" {
		return u.Host
	}
	return net.JoinHostPort(u.Hostname(), defaultPort)
}

func hasValue(m map[string]string, v string) bool {
	for _, x := range m {
		if x == v {
			return true
		}
	}
	return false
}

// dialTimeout bounds each endpoint; the monitor's tick has its own deadline.
const dialTimeout = 5 * time.Second

// Certs reads every certificate it can reach. One that cannot be read — the
// server is restarting, the file is not mounted on this node — is left out
// rather than reported: this monitor alerts on expiry, and the node-health
// monitor already owns "the database is down".
func (s InternalSource) Certs(ctx context.Context) []certEntry {
	var out []certEntry
	add := func(label string, notAfter time.Time, err error) {
		if err == nil {
			out = append(out, certEntry{Domain: label, Name: "internal", ExpiresAt: notAfter.Unix()})
		}
	}
	for label, path := range s.CAFiles {
		t, err := fileNotAfter(path)
		add(label, t, err)
	}
	if s.PostgresAddr != "" {
		t, err := postgresNotAfter(ctx, s.PostgresAddr)
		add("database (Postgres) server certificate", t, err)
	}
	for label, addr := range s.TLSAddrs {
		t, err := tlsNotAfter(ctx, addr)
		add(label, t, err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// fileNotAfter is the earliest expiry among the certificates in a PEM file: a
// bundle is only as good as the first certificate in it to lapse.
func fileNotAfter(path string) (time.Time, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	var earliest time.Time
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if earliest.IsZero() || cert.NotAfter.Before(earliest) {
			earliest = cert.NotAfter
		}
	}
	if earliest.IsZero() {
		return time.Time{}, fmt.Errorf("%s: no certificate found", path)
	}
	return earliest, nil
}

// readOnlyTLS is a client config for reading the date on whatever certificate a
// server presents. Verification is off ON PURPOSE and only here: the point is
// to report a certificate that has expired or is about to, and a verifying
// handshake refuses exactly that certificate. Nothing is sent over the
// connection and nothing read from it is trusted.
func readOnlyTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // see comment
}

func leafNotAfter(c *tls.Conn) (time.Time, error) {
	certs := c.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return time.Time{}, errors.New("server presented no certificate")
	}
	return certs[0].NotAfter, nil
}

func tlsNotAfter(ctx context.Context, addr string) (time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	d := tls.Dialer{Config: readOnlyTLS()}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()
	return leafNotAfter(conn.(*tls.Conn))
}

// postgresNotAfter asks a Postgres server for TLS the way a client does — the
// eight-byte SSLRequest, answered 'S' — and reads the certificate it presents.
// Postgres does not speak TLS until asked, so a plain TLS dial gets nothing.
func postgresNotAfter(ctx context.Context, addr string) (time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return time.Time{}, err
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}

	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req[0:4], 8)        // message length
	binary.BigEndian.PutUint32(req[4:8], 80877103) // SSLRequest code
	if _, err := raw.Write(req); err != nil {
		return time.Time{}, err
	}
	answer := make([]byte, 1)
	if _, err := raw.Read(answer); err != nil {
		return time.Time{}, err
	}
	if answer[0] != 'S' {
		return time.Time{}, errors.New("postgres does not offer TLS")
	}
	conn := tls.Client(raw, readOnlyTLS())
	if err := conn.HandshakeContext(ctx); err != nil {
		return time.Time{}, err
	}
	return leafNotAfter(conn)
}
