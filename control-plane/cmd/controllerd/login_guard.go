package main

import (
	"sync"
	"time"
)

// loginGuard is an in-memory brute-force limiter keyed by account (email). After
// maxFails consecutive failures within a rolling window, the account is locked
// for lockFor. It is per-node (resets on restart, not shared across HA nodes) —
// a DB-backed limiter for cluster-wide + restart-durable lockout is a follow-up.
type loginGuard struct {
	mu       sync.Mutex
	state    map[string]*loginState
	maxFails int
	lockFor  time.Duration
	window   time.Duration
}

type loginState struct {
	fails       int
	lastFail    time.Time
	lockedUntil time.Time
}

func newLoginGuard() *loginGuard {
	return &loginGuard{
		state:    make(map[string]*loginState),
		maxFails: 5,
		lockFor:  15 * time.Minute,
		window:   15 * time.Minute,
	}
}

// locked reports whether key is currently locked out and, if so, for how long.
func (g *loginGuard) locked(key string) (bool, time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.state[key]
	if st == nil {
		return false, 0
	}
	if now := time.Now(); now.Before(st.lockedUntil) {
		return true, time.Until(st.lockedUntil)
	}
	return false, 0
}

// recordFailure notes a failed attempt and locks the account once the threshold
// is crossed. Failures older than the window reset the counter.
func (g *loginGuard) recordFailure(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	st := g.state[key]
	if st == nil || now.Sub(st.lastFail) > g.window {
		st = &loginState{}
		g.state[key] = st
	}
	st.fails++
	st.lastFail = now
	if st.fails >= g.maxFails {
		st.lockedUntil = now.Add(g.lockFor)
	}
}

// recordSuccess clears any failure state for the account.
func (g *loginGuard) recordSuccess(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.state, key)
}

// loginAttempts is the process-wide login limiter.
var loginAttempts = newLoginGuard()
