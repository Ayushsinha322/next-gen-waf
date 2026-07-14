package main

import "testing"

func TestLoginGuardLockout(t *testing.T) {
	g := newLoginGuard() // maxFails=5
	key := "user@example.com"

	// Below the threshold: not locked.
	for i := 0; i < 4; i++ {
		g.recordFailure(key)
	}
	if locked, _ := g.locked(key); locked {
		t.Fatal("locked before reaching the failure threshold")
	}

	// 5th failure crosses the threshold → locked.
	g.recordFailure(key)
	locked, wait := g.locked(key)
	if !locked {
		t.Fatal("not locked after 5 failures")
	}
	if wait <= 0 {
		t.Errorf("expected a positive lockout duration, got %v", wait)
	}

	// A successful login clears the state.
	g.recordSuccess(key)
	if locked, _ := g.locked(key); locked {
		t.Error("still locked after recordSuccess")
	}

	// A different account is unaffected.
	if locked, _ := g.locked("other@example.com"); locked {
		t.Error("unrelated account is locked")
	}
}
