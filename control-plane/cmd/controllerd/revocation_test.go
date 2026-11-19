package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"
)

// A database that never answers: the lookup returns only when its context ends.
// Under context.Background() — what the checker used to pass — this never
// returned, and neither did the request waiting on it.
func TestRevocationCheckIsBoundedWhenTheDatabaseStalls(t *testing.T) {
	stalled := func(ctx context.Context, _ string) (bool, error) {
		<-ctx.Done()
		return false, ctx.Err()
	}
	check := revocationChecker(stalled, 30*time.Millisecond, zap.NewNop())

	done := make(chan bool, 1)
	go func() { done <- check("jti-1") }()
	select {
	case revoked := <-done:
		if revoked {
			t.Fatal("a failed lookup must fail open, not report the token revoked")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revocation check did not return: the lookup has no deadline")
	}
}

func TestRevocationCheckPassesTheAnswerThrough(t *testing.T) {
	for _, want := range []bool{true, false} {
		check := revocationChecker(func(context.Context, string) (bool, error) { return want, nil },
			time.Second, zap.NewNop())
		if got := check("jti"); got != want {
			t.Errorf("revoked = %v, want %v", got, want)
		}
	}
}

func TestRevocationCheckFailsOpenOnAnError(t *testing.T) {
	check := revocationChecker(func(context.Context, string) (bool, error) {
		return true, errors.New("connection refused")
	}, time.Second, zap.NewNop())
	if check("jti") {
		t.Fatal("an errored lookup must fail open")
	}
}
