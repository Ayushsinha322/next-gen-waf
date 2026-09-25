package logs

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// Opening the Logs page must show the NEWEST lines. Subscribe replayed the
// 200-entry backlog into a 64-slot channel with non-blocking sends, so all but
// the first ~64 were dropped — and the dropped ones were the most recent. On
// .71 (2026-09-25) the page showed 65 lines from a rolling update and none of
// the five attacks sent a minute later, though every hub had counted them.
func TestSubscribeReplaysTheWholeBacklogInOrder(t *testing.T) {
	h := newTestHub()
	for i := 0; i < 200; i++ {
		h.publish(Entry{Kind: "access", Data: json.RawMessage(fmt.Sprintf(`{"n":%d}`, i))})
	}

	ch := h.Subscribe()
	got := drain(ch, 200)
	if len(got) != 200 {
		t.Fatalf("replayed %d of 200 backlog entries — the newest %d were dropped", len(got), 200-len(got))
	}
	for i, e := range got {
		if want := fmt.Sprintf(`{"n":%d}`, i); string(e.Data) != want {
			t.Fatalf("entry %d = %s, want %s (backlog out of order)", i, e.Data, want)
		}
	}

	// A live entry published after subscribing arrives after the backlog.
	h.publish(Entry{Kind: "access", Data: json.RawMessage(`{"n":"live"}`)})
	if live := drain(ch, 1); len(live) != 1 || string(live[0].Data) != `{"n":"live"}` {
		t.Fatalf("live entry after the backlog: got %v", live)
	}
}

// drain reads up to n entries, giving a slow producer a moment before giving up.
func drain(ch chan Entry, n int) []Entry {
	var out []Entry
	for len(out) < n {
		select {
		case e := <-ch:
			out = append(out, e)
		case <-time.After(200 * time.Millisecond):
			return out
		}
	}
	return out
}
