package db

import (
	"encoding/json"
	"testing"
	"time"
)

// A row that carries a `diff` must still verify after a round trip through
// Postgres.
//
// This was found by running the newly-exposed verifier against the live
// deployment: 17 of 17 rows carrying a diff reported as ALTERED while every
// chain link was intact. The cause was not tampering — `diff` is stored as
// JSONB, which reorders keys, drops insignificant whitespace and renormalises
// numbers, and the MAC covered the exact bytes Go had marshalled. So every
// audited action that recorded a before/after was signed over one byte string
// and verified against another, permanently.
//
// It mattered more after failed logins started recording an outcome in `diff`:
// that made the single most security-relevant row type the one that could never
// be verified.

// jsonbLike models what Postgres hands back: same JSON, different bytes —
// keys reordered, whitespace gone.
func jsonbLike(t *testing.T, in string) json.RawMessage {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(in), &v); err != nil {
		t.Fatalf("fixture is not JSON: %v", err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	return json.RawMessage(b)
}

func TestAuditMACSurvivesJSONBRoundTrip(t *testing.T) {
	key := []byte("test-key-at-least-32-bytes-long!!!!")
	ts := time.Date(2026, 8, 27, 10, 30, 0, 123456000, time.UTC)
	tenant := "00000000-0000-0000-0000-000000000001"
	actor := "11111111-2222-3333-4444-555555555555"
	prev := make([]byte, 32)

	// What a handler writes: keys in source order, with spacing.
	written := json.RawMessage(`{"result":"FAILURE", "email":"attacker@evil.test", "reason":"invalid_credentials"}`)
	// What comes back out of JSONB: same document, different bytes.
	readBack := jsonbLike(t, string(written))

	if string(written) == string(readBack) {
		t.Fatal("fixture does not model the byte change; the test would prove nothing")
	}

	signed := auditChainMAC(key, 42, prev, tenant, &actor, "user.login", "user",
		nil, nil, nil, written, ts)
	recomputed := auditChainMAC(key, 42, prev, tenant, &actor, "user.login", "user",
		nil, nil, nil, readBack, ts)

	if string(signed) != string(recomputed) {
		t.Fatalf("a diff-carrying row does not verify after a JSONB round trip:\n written=%s\n readback=%s",
			written, readBack)
	}
}

// Canonicalisation must not flatten genuinely different documents into the same
// signature — that would let a diff be swapped without detection.
func TestCanonicalJSONStillDistinguishesContent(t *testing.T) {
	a := canonicalJSON(json.RawMessage(`{"result":"FAILURE"}`))
	b := canonicalJSON(json.RawMessage(`{"result":"SUCCESS"}`))
	if a == b {
		t.Fatal("FAILURE and SUCCESS canonicalise identically — the outcome would be forgeable")
	}
	// Key order is the only thing that may be normalised away.
	x := canonicalJSON(json.RawMessage(`{"a":1,"b":2}`))
	y := canonicalJSON(json.RawMessage(`{"b":2,"a":1}`))
	if x != y {
		t.Fatalf("key order must not change the signature: %q vs %q", x, y)
	}
}

func TestCanonicalJSONHandlesAbsentAndInvalid(t *testing.T) {
	if canonicalJSON(nil) != "" {
		t.Fatal("absent diff must canonicalise to the empty string, matching a NULL column")
	}
	if canonicalJSON(json.RawMessage("")) != "" {
		t.Fatal("empty diff must canonicalise to the empty string")
	}
	// Not JSON: signed as-is rather than silently becoming empty, which would
	// make two different malformed diffs share a signature.
	if got := canonicalJSON(json.RawMessage(`{not json`)); got != `{not json` {
		t.Fatalf("invalid JSON must be signed verbatim, got %q", got)
	}
}

// Rows signed before canonicalisation existed must not be reported as tampered
// merely because the signing rule improved. Both encodings use the same key, so
// accepting either is a representation choice, not a weakening.
func TestVerificationAcceptsLegacyDiffEncoding(t *testing.T) {
	key := []byte("test-key-at-least-32-bytes-long!!!!")
	ts := time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)
	tenant := "00000000-0000-0000-0000-000000000001"
	prev := make([]byte, 32)
	// Whitespace that canonicalisation removes, so the two forms differ.
	stored := json.RawMessage(`{"result": "SUCCESS",   "n": 1}`)

	legacy := auditChainMACRaw(key, 7, prev, tenant, nil, "site.update", "site", nil, nil, nil, stored, ts)
	canonical := auditChainMAC(key, 7, prev, tenant, nil, "site.update", "site", nil, nil, nil, stored, ts)

	if string(legacy) == string(canonical) {
		t.Skip("this input canonicalises to itself; the tolerance path is untestable with it")
	}
	if !auditRowVerifies(legacy, canonical, legacy) {
		t.Fatal("a legacy-signed row must still verify")
	}
	if !auditRowVerifies(canonical, canonical, legacy) {
		t.Fatal("a canonically-signed row must verify")
	}
	// A row signed with a DIFFERENT key must still fail under both forms.
	other := auditChainMAC([]byte("a-completely-different-key-32-bytes!"), 7, prev, tenant, nil,
		"site.update", "site", nil, nil, nil, stored, ts)
	if auditRowVerifies(other, canonical, legacy) {
		t.Fatal("tolerance must not accept a row signed with another key")
	}
}
