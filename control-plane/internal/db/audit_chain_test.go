package db

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func chainFixture() (key []byte, tid string, p func(string) *string, diff json.RawMessage, ts time.Time) {
	return []byte("test-key-0123456789-0123456789xx"),
		"00000000-0000-0000-0000-000000000001",
		func(s string) *string { return &s },
		json.RawMessage(`{"field":"value"}`),
		time.Unix(1700000000, 123456000).UTC()
}

// TestAuditChainMACBindsPositionAndPredecessor is the core property the previous
// per-row design lacked. A row's MAC must depend on WHERE it sits (seq) and WHAT
// CAME BEFORE it (prev_hmac), because that is what makes deletion and reordering
// detectable rather than silent.
func TestAuditChainMACBindsPositionAndPredecessor(t *testing.T) {
	key, tid, p, diff, ts := chainFixture()
	prev := bytes.Repeat([]byte{0xAB}, 32)

	base := auditChainMAC(key, 42, prev, tid, p("actor"), "site.create", "site", p("s1"), p("10.0.0.1"), p("curl"), diff, ts)

	if !bytes.Equal(base, auditChainMAC(key, 42, prev, tid, p("actor"), "site.create", "site", p("s1"), p("10.0.0.1"), p("curl"), diff, ts)) {
		t.Fatal("auditChainMAC is not deterministic")
	}

	cases := []struct {
		name string
		mac  []byte
	}{
		{"seq (row moved)", auditChainMAC(key, 43, prev, tid, p("actor"), "site.create", "site", p("s1"), p("10.0.0.1"), p("curl"), diff, ts)},
		{"prev_hmac (predecessor changed)", auditChainMAC(key, 42, bytes.Repeat([]byte{0xCD}, 32), tid, p("actor"), "site.create", "site", p("s1"), p("10.0.0.1"), p("curl"), diff, ts)},
		{"action", auditChainMAC(key, 42, prev, tid, p("actor"), "site.delete", "site", p("s1"), p("10.0.0.1"), p("curl"), diff, ts)},
		{"key", auditChainMAC([]byte("different-key-000000000000000000"), 42, prev, tid, p("actor"), "site.create", "site", p("s1"), p("10.0.0.1"), p("curl"), diff, ts)},
	}
	for _, c := range cases {
		if bytes.Equal(base, c.mac) {
			t.Errorf("chain MAC unchanged when %s — deletion/reordering would go undetected", c.name)
		}
	}
}

// TestChainMACDiffersFromLegacyMAC ensures the two schemes are domain-separated,
// so a legacy row's MAC can never be replayed as a valid chained row (which would
// let an attacker strip the chain fields and claim the row is pre-migration).
func TestChainMACDiffersFromLegacyMAC(t *testing.T) {
	key, tid, p, diff, ts := chainFixture()
	legacy := auditMAC(key, tid, p("actor"), "site.create", "site", p("s1"), p("10.0.0.1"), p("curl"), diff, ts)
	chained := auditChainMAC(key, 1, genesisPrevHMAC, tid, p("actor"), "site.create", "site", p("s1"), p("10.0.0.1"), p("curl"), diff, ts)
	if bytes.Equal(legacy, chained) {
		t.Fatal("chained and legacy MACs collide — schemes are not domain-separated")
	}
}

// TestChainMACLengthPrefixPreventsBoundaryConfusion guards the encoding itself.
// Concatenating variable-length fields without a length prefix lets two different
// (prev_hmac, fields) pairs produce the same byte stream, which would let an
// attacker shift bytes across the boundary and forge a valid-looking link.
func TestChainMACLengthPrefixPreventsBoundaryConfusion(t *testing.T) {
	key, tid, p, diff, ts := chainFixture()
	a := auditChainMAC(key, 1, []byte("AB"), tid, p("actor"), "x", "site", p("s1"), p("ip"), p("ua"), diff, ts)
	b := auditChainMAC(key, 1, []byte("A"), tid, p("actor"), "x", "site", p("s1"), p("ip"), p("ua"), diff, ts)
	if bytes.Equal(a, b) {
		t.Fatal("prev_hmac length is not bound into the MAC")
	}
}

// TestGenesisPrevHMACIsDistinctFromNil documents why genesis uses a fixed 32-byte
// zero block instead of NULL: NULL must unambiguously mean "written before the
// chain migration". If genesis were also NULL, an attacker could delete an entire
// tenant chain and present the remainder as legacy data.
func TestGenesisPrevHMACIsDistinctFromNil(t *testing.T) {
	if genesisPrevHMAC == nil {
		t.Fatal("genesisPrevHMAC must not be nil — NULL is reserved for pre-chain rows")
	}
	if len(genesisPrevHMAC) != 32 {
		t.Fatalf("genesisPrevHMAC length = %d, want 32 (sha256 size)", len(genesisPrevHMAC))
	}
	if !bytes.Equal(genesisPrevHMAC, make([]byte, 32)) {
		t.Fatal("genesisPrevHMAC must be all zeroes so it is a stable, well-known value")
	}
}

func TestAuditVerifyReportOK(t *testing.T) {
	if !(AuditVerifyReport{Checked: 10}).OK() {
		t.Error("a report with no findings should be OK")
	}
	for name, r := range map[string]AuditVerifyReport{
		"altered":  {Altered: []string{"id"}},
		"broken":   {ChainBroken: []string{"id"}},
		"seq gaps": {SeqGaps: []string{"tenant X: seq 1 -> 3"}},
	} {
		if r.OK() {
			t.Errorf("report with %s must not be OK", name)
		}
	}
	// Unchained legacy rows are reported but are not themselves a failure.
	if !(AuditVerifyReport{Checked: 5, Unchained: 5}).OK() {
		t.Error("pre-migration rows alone should not fail verification")
	}
}
