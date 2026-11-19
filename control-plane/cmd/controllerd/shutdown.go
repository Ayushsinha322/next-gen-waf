package main

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// The order the control plane stops in, and why it is its own function.
//
// It used to be three lines at the end of run(): close the database pool, then
// shut the HTTP server down, with the leader elector stopped by a `defer` that
// only ran after both. On the leader that order cannot finish. The elector
// holds one pool connection for as long as it holds the advisory lock, and
// closing a pgx pool blocks until every connection is returned — so pool.Close()
// waited on the elector, which was waiting for run() to return, which was
// waiting on pool.Close(). Every stop of the leading node sat there until
// Docker's timeout and was SIGKILLed: leadership was never resigned (the
// successor had to wait for Postgres to notice the dead connection), in-flight
// API calls were cut, and each roll of that node cost the full stop timeout.
//
// The order now:
//
//  1. Resign leadership. It needs the database, and it lets a follower take
//     over while this node is still finishing its requests.
//  2. End long-lived streams (the live-log SSE). They never go idle, so without
//     this http.Server.Shutdown always ran to its deadline whenever a console
//     tab had the Logs page open.
//  3. Shut the HTTP server down: no new connections, in-flight requests finish
//     within httpGrace; whatever is still open then is closed.
//  4. Close the pool, bounded — a handler that outlived step 3 must not be able
//     to hold the process open.
//
// compose's stop_grace_period for the control plane (30s) is sized to this:
// 2 × the elector's 5 s operation timeout + httpGrace + poolGrace.
type shutdownSteps struct {
	log *zap.Logger

	stopElector  func()                          // nil in standalone mode
	stopStreams  func()                          // ends SSE responses
	httpShutdown func(ctx context.Context) error // http.Server.Shutdown
	httpClose    func() error                    // http.Server.Close
	closePool    func()                          // nil without a database

	httpGrace time.Duration
	poolGrace time.Duration
}

const (
	defaultHTTPGrace = 10 * time.Second
	defaultPoolGrace = 5 * time.Second
)

// run performs the steps in order and returns the HTTP shutdown error, if any.
func (s shutdownSteps) run() error {
	if s.stopElector != nil {
		s.stopElector()
	}
	if s.stopStreams != nil {
		s.stopStreams()
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.httpGrace)
	err := s.httpShutdown(ctx)
	cancel()
	if err != nil {
		s.log.Warn("HTTP server did not drain in time; closing remaining connections",
			zap.Duration("grace", s.httpGrace), zap.Error(err))
		if s.httpClose != nil {
			_ = s.httpClose()
		}
	}

	if s.closePool != nil {
		closed := make(chan struct{})
		go func() {
			s.closePool()
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(s.poolGrace):
			s.log.Warn("database pool did not close in time; exiting with connections still out",
				zap.Duration("grace", s.poolGrace))
		}
	}
	return err
}

// stopSignal is a channel that can be closed more than once.
type stopSignal struct {
	ch   chan struct{}
	once sync.Once
}

func newStopSignal() *stopSignal { return &stopSignal{ch: make(chan struct{})} }

func (s *stopSignal) stop()                 { s.once.Do(func() { close(s.ch) }) }
func (s *stopSignal) done() <-chan struct{} { return s.ch }

// streams is stopped when shutdown begins. A handler that holds a response open
// indefinitely selects on streams.done() next to its request context.
var streams = newStopSignal()
