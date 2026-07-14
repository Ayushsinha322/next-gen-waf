package db

import (
	"strings"
	"testing"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	pw := "correct-horse-battery-staple-42"
	h, err := hashPassword(pw)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !strings.HasPrefix(h, "argon2id$") {
		t.Errorf("hash not argon2id-encoded: %q", h)
	}
	if !checkPassword(pw, h) {
		t.Error("checkPassword rejected the correct password")
	}
	if checkPassword("wrong-password", h) {
		t.Error("checkPassword accepted a wrong password")
	}
	// Salt is random → two hashes of the same password must differ.
	h2, _ := hashPassword(pw)
	if h == h2 {
		t.Error("hashPassword produced identical output for two calls (salt not random)")
	}
}

func TestGenerateAndHashAPIKey(t *testing.T) {
	k1, err := generateAPIKey()
	if err != nil {
		t.Fatalf("generateAPIKey: %v", err)
	}
	k2, _ := generateAPIKey()
	if k1 == k2 {
		t.Error("generateAPIKey returned identical keys")
	}
	if !strings.HasPrefix(k1, "sk-live-") {
		t.Errorf("key missing sk-live- prefix: %q", k1)
	}
	if len(k1) < 40 {
		t.Errorf("key too short to be 32 random bytes: %q", k1)
	}
	// Hash is deterministic per key and differs across keys.
	if hashAPIKey(k1) != hashAPIKey(k1) {
		t.Error("hashAPIKey is not deterministic")
	}
	if hashAPIKey(k1) == hashAPIKey(k2) {
		t.Error("hashAPIKey collided for different keys")
	}
	// Preview must never expose the full secret.
	p := keyPreview(k1)
	if strings.Contains(p, k1) || len(p) >= len(k1) {
		t.Errorf("preview leaks the key: %q", p)
	}
}
