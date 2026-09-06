package jobs

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTrackRecordsOutcomeAndRunNow(t *testing.T) {
	calls := 0
	j := Register("t.refresh", "test", time.Hour, func(ctx context.Context) (string, error) {
		calls++
		if calls == 2 {
			return "", errors.New("feed down")
		}
		return "ok note", nil
	})
	j.Track(func() (string, error) { return "tick", nil })
	s := Snapshot()
	if len(s) < 1 || s[0].Runs != 1 || s[0].LastNote != "tick" || s[0].LastError != "" || s[0].NextDue == nil {
		t.Fatalf("after one tick: %+v", s)
	}
	st, err := RunNow(context.Background(), "t.refresh")
	if err != nil || st.Runs != 2 || st.LastNote != "ok note" {
		t.Fatalf("run now: %v %+v", err, st)
	}
	st, err = RunNow(context.Background(), "t.refresh")
	if err == nil || st.Failures != 1 || st.LastError != "feed down" {
		t.Fatalf("failed run must be recorded: %v %+v", err, st)
	}
	if _, err := RunNow(context.Background(), "nope"); !errors.Is(err, ErrUnknown) {
		t.Fatal("unknown job must be refused")
	}
	Register("t.norun", "no runner", time.Minute, nil)
	if _, err := RunNow(context.Background(), "t.norun"); !errors.Is(err, ErrNotRunnable) {
		t.Fatal("job without runner must be refused")
	}
	// Re-registering replaces, not duplicates (monitors are rebuilt on leadership).
	Register("t.refresh", "test again", time.Hour, nil)
	n := 0
	for _, s := range Snapshot() {
		if s.Name == "t.refresh" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("expected one t.refresh, got %d", n)
	}
	Unregister("t.refresh")
	Unregister("t.norun")
}
