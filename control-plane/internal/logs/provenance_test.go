package logs

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// newProvenanceHub builds a Hub with the maps and channels publish() touches,
// without starting any file tailers.
func newProvenanceHub() *Hub {
	h := newTestHub()
	h.subs = make(map[chan Entry]struct{})
	h.done = make(chan struct{})
	return h
}

func TestPublishDefaultsSourceToLive(t *testing.T) {
	// A real emitter that forgets to set Source must not produce an entry with
	// empty provenance — it must read as live.
	h := newProvenanceHub()
	sub := h.Subscribe()

	h.publish(Entry{Kind: "waf", Data: json.RawMessage(`{"ip":"1.2.3.4"}`)})

	select {
	case got := <-sub:
		if got.Source != SourceLive {
			t.Fatalf("Source = %q, want %q", got.Source, SourceLive)
		}
		if got.IsSimulated() {
			t.Error("a live entry reported itself as simulated")
		}
	case <-time.After(time.Second):
		t.Fatal("no entry delivered")
	}
}

func TestPublishPreservesSimulatedSource(t *testing.T) {
	h := newProvenanceHub()
	sub := h.Subscribe()

	h.publish(Entry{Kind: "waf", Data: json.RawMessage(`{}`), Source: SourceSimulated})

	select {
	case got := <-sub:
		if got.Source != SourceSimulated {
			t.Fatalf("Source = %q, want %q", got.Source, SourceSimulated)
		}
		if !got.IsSimulated() {
			t.Error("a simulated entry did not report itself as simulated")
		}
	case <-time.After(time.Second):
		t.Fatal("no entry delivered")
	}
}

func TestSimulatedProvenanceSurvivesJSON(t *testing.T) {
	// The dashboard reads this over SSE, so the marker has to be on the wire.
	b, err := json.Marshal(Entry{Kind: "waf", Data: json.RawMessage(`{}`), Source: SourceSimulated})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round Entry
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if round.Source != SourceSimulated {
		t.Fatalf("Source lost in serialization: %q (raw: %s)", round.Source, b)
	}
	if !strings.Contains(string(b), `"source":"simulated"`) {
		t.Errorf("serialized entry does not carry an explicit source marker: %s", b)
	}
}

func TestSimulatorIsOffByDefault(t *testing.T) {
	// The central guarantee: absent a deliberate opt-in, nothing is fabricated.
	t.Setenv(SimulatorEnvVar, "")
	if SimulatorEnabled() {
		t.Fatal("simulator reported enabled with the env var unset")
	}

	h := newProvenanceHub()
	if h.StartSimulator() {
		t.Fatal("StartSimulator ran without an explicit opt-in")
	}

	sub := h.Subscribe()
	select {
	case got := <-sub:
		t.Fatalf("simulator published %q despite being disabled", got.Kind)
	case <-time.After(600 * time.Millisecond):
		// Correct: an unconfigured deployment observes nothing and says nothing.
		// The fastest simulator ticker is 280ms, so this window would have caught it.
	}
}

func TestSimulatorRequiresExactOptIn(t *testing.T) {
	// Only "1" enables it — no truthy-string guessing, so a stray value cannot
	// quietly turn fabrication on.
	for _, v := range []string{"", "0", "true", "yes", "on", "TRUE", "2"} {
		t.Setenv(SimulatorEnvVar, v)
		if SimulatorEnabled() {
			t.Errorf("SENTINEL_DEV_SIMULATOR=%q enabled the simulator", v)
		}
	}
	t.Setenv(SimulatorEnvVar, "1")
	if !SimulatorEnabled() {
		t.Error(`SENTINEL_DEV_SIMULATOR="1" did not enable the simulator`)
	}
}

func TestSimulatorTagsEverythingItEmits(t *testing.T) {
	t.Setenv(SimulatorEnvVar, "1")
	h := newProvenanceHub()
	sub := h.Subscribe()

	if !h.StartSimulator() {
		t.Fatal("simulator did not start with the opt-in set")
	}

	deadline := time.After(3 * time.Second)
	seen := 0
	for seen < 5 {
		select {
		case got := <-sub:
			seen++
			if got.Source != SourceSimulated {
				t.Fatalf("simulator emitted %q with Source=%q, want %q", got.Kind, got.Source, SourceSimulated)
			}
		case <-deadline:
			t.Fatalf("only saw %d simulated entries before timeout", seen)
		}
	}
}
