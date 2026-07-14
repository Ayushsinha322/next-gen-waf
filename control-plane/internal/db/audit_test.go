package db

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// TestAuditMACDeterministicAndTamperEvident proves the audit HMAC is genuinely
// verifiable: it is a pure function of the persisted fields (so WriteAuditLog
// and VerifyAuditLog compute the identical value), and any change to any signed
// field — or the key — changes the MAC (tamper-evident). This is the property
// the previous implementation lacked, because it signed an unstored timestamp.
func TestAuditMACDeterministicAndTamperEvident(t *testing.T) {
	key := []byte("test-key-0123456789-0123456789xx")
	tid := "00000000-0000-0000-0000-000000000001"
	actor := "11111111-1111-1111-1111-111111111111"
	target := "site-1"
	ip := "10.0.0.1"
	ua := "curl/8.0"
	diff := json.RawMessage(`{"field":"value"}`)
	// Microsecond precision to mirror what Postgres round-trips.
	ts := time.Unix(1700000000, 123456000).UTC()

	p := func(s string) *string { return &s }
	base := auditMAC(key, tid, p(actor), "site.create", "site", p(target), p(ip), p(ua), diff, ts)

	// Deterministic: identical inputs → identical MAC.
	if !bytes.Equal(base, auditMAC(key, tid, p(actor), "site.create", "site", p(target), p(ip), p(ua), diff, ts)) {
		t.Fatal("auditMAC is not deterministic for identical inputs")
	}

	// Tamper-evident: changing any signed field (or the key) changes the MAC.
	cases := []struct {
		name string
		mac  []byte
	}{
		{"tenant", auditMAC(key, "99999999-9999-9999-9999-999999999999", p(actor), "site.create", "site", p(target), p(ip), p(ua), diff, ts)},
		{"actor", auditMAC(key, tid, p("22222222-2222-2222-2222-222222222222"), "site.create", "site", p(target), p(ip), p(ua), diff, ts)},
		{"action", auditMAC(key, tid, p(actor), "site.delete", "site", p(target), p(ip), p(ua), diff, ts)},
		{"targetKind", auditMAC(key, tid, p(actor), "site.create", "rule", p(target), p(ip), p(ua), diff, ts)},
		{"targetID", auditMAC(key, tid, p(actor), "site.create", "site", p("site-2"), p(ip), p(ua), diff, ts)},
		{"ip", auditMAC(key, tid, p(actor), "site.create", "site", p(target), p("10.0.0.2"), p(ua), diff, ts)},
		{"userAgent", auditMAC(key, tid, p(actor), "site.create", "site", p(target), p(ip), p("wget"), diff, ts)},
		{"diff", auditMAC(key, tid, p(actor), "site.create", "site", p(target), p(ip), p(ua), json.RawMessage(`{"field":"tampered"}`), ts)},
		{"timestamp", auditMAC(key, tid, p(actor), "site.create", "site", p(target), p(ip), p(ua), diff, ts.Add(time.Second))},
		{"key", auditMAC([]byte("different-key-000000000000000000"), tid, p(actor), "site.create", "site", p(target), p(ip), p(ua), diff, ts)},
	}
	for _, c := range cases {
		if bytes.Equal(base, c.mac) {
			t.Errorf("MAC did not change when %q was altered — not tamper-evident", c.name)
		}
	}
}
