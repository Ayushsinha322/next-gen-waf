// Package jobs is the control plane's registry of background work, so the
// console can show what runs, when it last ran, how it went, and run it now.
//
// Before this the threat-intel refresh, certificate-expiry check, node-health
// sweep, disk-pressure check and alert auto-resolve all ran invisibly; the only
// trace was "freshness 59m ago" on one page. A worker registers itself once and
// wraps each tick in Track; the registry keeps the last outcome per job.
package jobs

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// Status is one job as the console sees it.
type Status struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Interval    string  `json:"interval"`
	IntervalSec int64   `json:"interval_secs"`
	Running     bool    `json:"running"`
	Runs        int64   `json:"runs"`
	Failures    int64   `json:"failures"`
	LastStart   *string `json:"last_start,omitempty"`
	LastEnd     *string `json:"last_end,omitempty"`
	LastMs      int64   `json:"last_duration_ms"`
	LastError   string  `json:"last_error,omitempty"`
	LastNote    string  `json:"last_note,omitempty"`
	NextDue     *string `json:"next_due,omitempty"`
	CanRunNow   bool    `json:"can_run_now"`
}

// Job is a registered worker. Workers call Track around each tick.
type Job struct {
	name, desc string
	interval   time.Duration
	runner     func(ctx context.Context) (note string, err error)

	mu        sync.Mutex
	running   bool
	runs      int64
	failures  int64
	lastStart time.Time
	lastEnd   time.Time
	lastErr   string
	lastNote  string
}

var (
	regMu sync.RWMutex
	reg   = map[string]*Job{}
)

// Register adds (or replaces, by name) a job. runner may be nil for jobs that
// cannot be triggered on demand. Replacing matters: monitors are rebuilt on
// every leadership acquisition and must not leave stale duplicates behind.
func Register(name, desc string, interval time.Duration, runner func(ctx context.Context) (string, error)) *Job {
	j := &Job{name: name, desc: desc, interval: interval, runner: runner}
	regMu.Lock()
	reg[name] = j
	regMu.Unlock()
	return j
}

// Unregister removes a job (a monitor stopping on leadership loss).
func Unregister(name string) {
	regMu.Lock()
	delete(reg, name)
	regMu.Unlock()
}

// Track records one tick: start time, duration, outcome. fn returns a short
// human note ("19,753 indicators", "3 nodes checked") and an error.
func (j *Job) Track(fn func() (string, error)) {
	if j == nil {
		fn() //nolint:errcheck // nothing to record against
		return
	}
	j.mu.Lock()
	j.running = true
	j.lastStart = time.Now()
	j.mu.Unlock()
	note, err := fn()
	j.mu.Lock()
	j.running = false
	j.lastEnd = time.Now()
	j.runs++
	j.lastNote = note
	if err != nil {
		j.failures++
		j.lastErr = err.Error()
	} else {
		j.lastErr = ""
	}
	j.mu.Unlock()
}

func (j *Job) status(now time.Time) Status {
	j.mu.Lock()
	defer j.mu.Unlock()
	s := Status{
		Name: j.name, Description: j.desc, Interval: j.interval.String(), IntervalSec: int64(j.interval / time.Second),
		Running: j.running, Runs: j.runs, Failures: j.failures, LastError: j.lastErr, LastNote: j.lastNote,
		CanRunNow: j.runner != nil,
	}
	if !j.lastStart.IsZero() {
		t := j.lastStart.UTC().Format(time.RFC3339)
		s.LastStart = &t
	}
	if !j.lastEnd.IsZero() {
		t := j.lastEnd.UTC().Format(time.RFC3339)
		s.LastEnd = &t
		s.LastMs = j.lastEnd.Sub(j.lastStart).Milliseconds()
		if j.interval > 0 {
			n := j.lastEnd.Add(j.interval)
			if n.Before(now) {
				n = now
			}
			ns := n.UTC().Format(time.RFC3339)
			s.NextDue = &ns
		}
	}
	return s
}

// Snapshot lists every registered job, sorted by name.
func Snapshot() []Status {
	now := time.Now()
	regMu.RLock()
	out := make([]Status, 0, len(reg))
	for _, j := range reg {
		out = append(out, j.status(now))
	}
	regMu.RUnlock()
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

// ErrNotRunnable is returned for jobs registered without a runner.
var ErrNotRunnable = errors.New("job cannot be run on demand")

// ErrUnknown is returned for a name nobody registered.
var ErrUnknown = errors.New("unknown job")

// ErrBusy is returned when the job is already mid-run.
var ErrBusy = errors.New("job is already running")

// RunNow executes the job's runner immediately, tracked like a scheduled tick.
// Refuses to overlap a run already in progress.
func RunNow(ctx context.Context, name string) (Status, error) {
	regMu.RLock()
	j, ok := reg[name]
	regMu.RUnlock()
	if !ok {
		return Status{}, ErrUnknown
	}
	if j.runner == nil {
		return j.status(time.Now()), ErrNotRunnable
	}
	j.mu.Lock()
	if j.running {
		j.mu.Unlock()
		return j.status(time.Now()), ErrBusy
	}
	j.mu.Unlock()
	var runErr error
	j.Track(func() (string, error) {
		note, err := j.runner(ctx)
		runErr = err
		return note, err
	})
	return j.status(time.Now()), runErr
}
