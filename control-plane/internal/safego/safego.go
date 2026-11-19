// Package safego starts the control plane's background goroutines so that a
// panic in one of them is contained instead of ending the process.
//
// # THE PROBLEM IT EXISTS FOR
//
// Go ends the whole process when any goroutine panics. The REST API was never
// exposed to that — gin.Recovery turns a handler panic into a 500 — but nothing
// covered the two dozen background loops: alerting, threat-intel fetching, the
// certificate and disk monitors, scheduled reports, the log hub. Several of
// them parse data the control plane does not control (a feed's body, a log
// line, a row another version wrote). One unexpected value there killed the
// control plane, and because every node reads the same database and the same
// logs, the replacement — and the other two nodes — could die on the same
// value: a crash loop with the console down until someone found the row.
//
// The data plane has had the equivalent guard since 1.1.16 (panic_guard.rs).
//
// # WHAT CONTAINMENT MEANS HERE
//
// A recovered panic is logged at ERROR with its stack and counted (Panics,
// reported on the health endpoint). A Loop is run again after a backoff, so a
// transient fault costs one tick and a persistent one costs a line a minute —
// loud, but with the API and every other loop still running. Nothing is
// swallowed silently: a subsystem that keeps panicking keeps saying so.
package safego

import (
	"runtime/debug"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

var panics atomic.Uint64

// Panics is the number of background panics recovered since the process
// started. Zero is the only healthy value.
func Panics() uint64 { return panics.Load() }

// Backoff between restarts of a panicking Loop: first, and ceiling. A loop that
// then runs for healthyAfter without panicking starts again from the first.
// Variables, not constants, so the tests do not wait a second per restart.
var (
	backoffFirst = time.Second
	backoffMax   = time.Minute
	healthyAfter = 5 * time.Minute
)

// Recover is for `defer safego.Recover(log, name)` at the top of a goroutine
// that must not take the process down. It has to be deferred directly:
// recover() only stops a panic from the deferred function itself.
func Recover(log *zap.Logger, name string) {
	if r := recover(); r != nil {
		report(log, name, r)
	}
}

// Caught reports r if it is a recovered panic and says whether it was one. It
// is for a goroutine that has something to record when it panics:
//
//	defer func() {
//		if safego.Caught(log, name, recover()) {
//			results[i].Error = "internal error"
//		}
//	}()
func Caught(log *zap.Logger, name string, r any) bool {
	if r == nil {
		return false
	}
	report(log, name, r)
	return true
}

func report(log *zap.Logger, name string, r any) {
	n := panics.Add(1)
	if log == nil {
		log = zap.L()
	}
	log.Error("background task panicked; contained",
		zap.String("task", name),
		zap.Any("panic", r),
		zap.Uint64("panics_total", n),
		zap.ByteString("stack", debug.Stack()),
	)
}

// Go runs fn in a new goroutine. If fn panics the panic is reported and the
// goroutine ends; the process carries on. Use it for one-shot work.
func Go(log *zap.Logger, name string, fn func()) {
	go func() {
		defer Recover(log, name)
		fn()
	}()
}

// Loop runs fn in a new goroutine and, if fn panics, runs it again after a
// backoff. A normal return ends the loop — that is how fn says it was stopped.
//
// fn must be safe to enter twice: it may `defer ticker.Stop()`, but it must not
// close a channel or otherwise do once-only work on its way out.
//
// The leader elector is deliberately NOT run this way. A panic in the code that
// decides who may write should end the process: the lock connection drops,
// another node takes over, and no node carries on believing a leadership it can
// no longer confirm.
func Loop(log *zap.Logger, name string, fn func()) {
	go func() {
		wait := backoffFirst
		for {
			started := time.Now()
			if !runOnce(log, name, fn) {
				return
			}
			if time.Since(started) >= healthyAfter {
				wait = backoffFirst
			}
			time.Sleep(wait)
			if wait *= 2; wait > backoffMax {
				wait = backoffMax
			}
		}
	}()
}

// runOnce runs fn and reports whether it panicked.
func runOnce(log *zap.Logger, name string, fn func()) (panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			report(log, name, r)
			panicked = true
		}
	}()
	fn()
	return false
}
