package db

// TLS posture verification for the Postgres connection.
//
// The control plane used to connect over PLAINTEXT: every shipped DSN had
// sslmode=disable, and the compose Postgres was stock postgres:16-alpine with no
// certificate and no ssl=on, so it could not have accepted TLS even if asked.
// Session tokens, API-key hashes, audit rows, tenant configuration and the
// handshake credentials all crossed the network in the clear.
//
// These tests assert the fix is real rather than cosmetic: that a verify-full
// connection is actually encrypted (checked against pg_stat_ssl on the server, not
// just "the connection succeeded"), and that verification FAILS CLOSED when the CA
// is wrong or the hostname is absent from the certificate's SAN. A DSN that says
// verify-full while silently accepting any certificate would be worse than
// plaintext, because it would look secure.
//
// Requires a TLS-enabled Postgres, which the default test database is not, so these
// skip unless explicitly pointed at one:
//
//	PKI_DIR=/tmp/pki PG_UID=$(id -u) PG_GID=$(id -g) \
//	  bash deploy/docker/issue-postgres-cert.sh
//	# start Postgres with ssl=on and those certs, then:
//	PGTLS_BASE=127.0.0.1:5432 PGTLS_CA=/tmp/pki/root.crt \
//	  PGTLS_BOGUS_CA=/tmp/pki/other-ca.crt PGTLS_WRONG_HOST=127.0.0.2:5432 \
//	  go test ./internal/db/ -run TestPostgresTLS -v

import (
	"context"
	"os"
	"strings"
	"testing"
)

// Proves the DSN change is real: verify-full succeeds against the internal CA,
// and fails closed when the CA is wrong or the hostname does not match the SAN.
func TestPostgresTLSVerifyFull(t *testing.T) {
	base := os.Getenv("PGTLS_BASE") // host:port
	ca := os.Getenv("PGTLS_CA")
	if base == "" || ca == "" {
		t.Skip("PGTLS_BASE/PGTLS_CA not set")
	}
	ctx := context.Background()

	t.Run("verify-full with the correct CA connects", func(t *testing.T) {
		dsn := "postgres://sentinel:testpass@" + base + "/sentinel?sslmode=verify-full&sslrootcert=" + ca
		pool, err := Open(ctx, Config{URL: dsn, MaxConns: 2, MinConns: 1})
		if err != nil {
			t.Fatalf("verify-full connection failed: %v", err)
		}
		defer pool.Close()
		pg := pool.(*pgxPool)
		var ssl bool
		if err := pg.pool.QueryRow(ctx,
			`SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()`).Scan(&ssl); err != nil {
			t.Fatalf("querying pg_stat_ssl: %v", err)
		}
		if !ssl {
			t.Fatal("connected, but the server reports the session is NOT encrypted")
		}
	})

	t.Run("verify-full rejects an untrusted CA", func(t *testing.T) {
		bogus := os.Getenv("PGTLS_BOGUS_CA")
		if bogus == "" {
			t.Skip("PGTLS_BOGUS_CA not set")
		}
		dsn := "postgres://sentinel:testpass@" + base + "/sentinel?sslmode=verify-full&sslrootcert=" + bogus
		pool, err := Open(ctx, Config{URL: dsn, MaxConns: 2, MinConns: 1})
		if err == nil {
			pool.Close()
			t.Fatal("connected with an untrusted CA — verify-full is not actually verifying")
		}
		t.Logf("correctly rejected: %v", err)
	})

	t.Run("verify-full rejects a hostname absent from the SAN", func(t *testing.T) {
		wrongHost := os.Getenv("PGTLS_WRONG_HOST")
		if wrongHost == "" {
			t.Skip("PGTLS_WRONG_HOST not set")
		}
		dsn := "postgres://sentinel:testpass@" + wrongHost + "/sentinel?sslmode=verify-full&sslrootcert=" + ca
		pool, err := Open(ctx, Config{URL: dsn, MaxConns: 2, MinConns: 1})
		if err == nil {
			pool.Close()
			t.Fatal("connected to a hostname not in the SAN — verify-full is not checking the name")
		}
		if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "SAN") &&
			!strings.Contains(err.Error(), "valid for") {
			t.Logf("rejected, though not obviously for a name mismatch: %v", err)
		}
	})
}
