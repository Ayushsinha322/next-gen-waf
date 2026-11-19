package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

type callLog struct {
	mu    sync.Mutex
	calls []string
}

func (c *callLog) add(s string) { c.mu.Lock(); c.calls = append(c.calls, s); c.mu.Unlock() }
func (c *callLog) got() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

// The leader's elector holds a pool connection until it is stopped, and closing
// the pool blocks until that connection comes back. This fake pool behaves the
// same way, so a shutdown that closes the pool before stopping the elector —
// the order run() used to have — hangs here exactly as it hung in production.
func TestShutdownStopsTheElectorBeforeClosingThePool(t *testing.T) {
	var log callLog
	electorStopped := make(chan struct{})

	s := shutdownSteps{
		log:          zap.NewNop(),
		stopElector:  func() { log.add("elector"); close(electorStopped) },
		stopStreams:  func() { log.add("streams") },
		httpShutdown: func(context.Context) error { log.add("http"); return nil },
		closePool:    func() { <-electorStopped; log.add("pool") },
		httpGrace:    time.Second,
		poolGrace:    time.Second,
	}

	done := make(chan error, 1)
	go func() { done <- s.run() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown hung: the pool was closed while the elector still held its connection")
	}

	want := []string{"elector", "streams", "http", "pool"}
	got := log.got()
	if len(got) != len(want) {
		t.Fatalf("calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("calls = %v, want %v", got, want)
		}
	}
}

func TestShutdownClosesWhatDidNotDrain(t *testing.T) {
	var log callLog
	s := shutdownSteps{
		log: zap.NewNop(),
		httpShutdown: func(ctx context.Context) error {
			<-ctx.Done() // a response that never ends
			return ctx.Err()
		},
		httpClose: func() error { log.add("close"); return nil },
		httpGrace: 20 * time.Millisecond,
		poolGrace: time.Second,
	}
	err := s.run()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if got := log.got(); len(got) != 1 || got[0] != "close" {
		t.Fatalf("calls = %v, want the server closed after the grace", got)
	}
}

func TestShutdownDoesNotWaitForeverOnThePool(t *testing.T) {
	never := make(chan struct{})
	t.Cleanup(func() { close(never) })
	s := shutdownSteps{
		log:          zap.NewNop(),
		httpShutdown: func(context.Context) error { return nil },
		closePool:    func() { <-never },
		httpGrace:    time.Second,
		poolGrace:    20 * time.Millisecond,
	}
	done := make(chan struct{})
	go func() { _ = s.run(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a pool that never closes held shutdown open")
	}
}

func TestShutdownWithoutClusterOrDatabase(t *testing.T) {
	s := shutdownSteps{
		log:          zap.NewNop(),
		httpShutdown: func(context.Context) error { return nil },
		httpGrace:    time.Second,
		poolGrace:    time.Second,
	}
	if err := s.run(); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestStopSignalCanBeStoppedTwice(t *testing.T) {
	s := newStopSignal() // not the process-wide one: other tests stream
	select {
	case <-s.done():
		t.Fatal("stopped before stop()")
	default:
	}
	s.stop()
	s.stop() // a second close would panic
	select {
	case <-s.done():
	default:
		t.Fatal("not stopped")
	}
}
