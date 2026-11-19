package safego

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func fastBackoff(t *testing.T) {
	t.Helper()
	f, m, h := backoffFirst, backoffMax, healthyAfter
	backoffFirst, backoffMax, healthyAfter = time.Millisecond, 4*time.Millisecond, time.Hour
	t.Cleanup(func() { backoffFirst, backoffMax, healthyAfter = f, m, h })
}

func observed() (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(zap.ErrorLevel)
	return zap.New(core), logs
}

// A panic in a goroutine started with plain `go` ends the test binary, so every
// test here is also the proof that the panic did not escape.

func TestGoContainsAPanicAndReportsIt(t *testing.T) {
	log, logs := observed()
	before := Panics()
	done := make(chan struct{})
	Go(log, "one-shot", func() {
		defer close(done)
		var m map[string]int
		m["feed"] = 1 // nil map write: the shape of a parser hitting bad data
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine did not run")
	}
	// The count moves before the line is written; wait for the line.
	waitFor(t, func() bool {
		return logs.FilterMessage("background task panicked; contained").Len() == 1
	})
	if got := Panics(); got != before+1 {
		t.Errorf("Panics() = %d, want %d", got, before+1)
	}
	entries := logs.FilterMessage("background task panicked; contained").All()
	if len(entries) != 1 {
		t.Fatalf("want one report, got %d", len(entries))
	}
	ctx := entries[0].ContextMap()
	if ctx["task"] != "one-shot" {
		t.Errorf("task = %v", ctx["task"])
	}
	if stack, _ := ctx["stack"].(string); stack == "" {
		t.Error("report carries no stack")
	}
}

func TestLoopRunsAgainAfterAPanic(t *testing.T) {
	fastBackoff(t)
	log, logs := observed()
	var runs atomic.Int32
	stopped := make(chan struct{})
	Loop(log, "monitor", func() {
		if runs.Add(1) < 3 {
			panic("bad row")
		}
		close(stopped) // third entry: behaves, and returns as a stopped loop does
	})
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatalf("loop was not restarted after a panic (runs=%d)", runs.Load())
	}
	if n := logs.FilterMessage("background task panicked; contained").Len(); n != 2 {
		t.Errorf("want 2 reports, got %d", n)
	}
}

func TestLoopEndsOnANormalReturn(t *testing.T) {
	fastBackoff(t)
	var runs atomic.Int32
	Loop(zap.NewNop(), "stopped", func() { runs.Add(1) })
	time.Sleep(50 * time.Millisecond)
	if n := runs.Load(); n != 1 {
		t.Fatalf("a loop that returned was entered %d times; a stopped monitor must stay stopped", n)
	}
}

func TestRecoverLetsEarlierDefersRun(t *testing.T) {
	// The fan-out shape: `defer wg.Done()` then `defer Recover(...)`. Without
	// the recover the WaitGroup would never be released — and the process
	// would be gone anyway.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer Recover(zap.NewNop(), "fan-out")
		panic("one source's parser")
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("WaitGroup never released")
	}
}

func TestANilLoggerIsTolerated(t *testing.T) {
	done := make(chan struct{})
	Go(nil, "nil-logger", func() { defer close(done); panic("x") })
	<-done
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestCaughtReportsOnlyARealPanic(t *testing.T) {
	log, logs := observed()
	if Caught(log, "none", nil) {
		t.Fatal("nil is not a panic")
	}
	var recorded string
	func() {
		defer func() {
			if Caught(log, "fan-out", recover()) {
				recorded = "internal error"
			}
		}()
		panic("boom")
	}()
	if recorded != "internal error" {
		t.Fatal("the goroutine could not record its own failure")
	}
	if n := logs.FilterMessage("background task panicked; contained").Len(); n != 1 {
		t.Fatalf("want one report, got %d", n)
	}
}
