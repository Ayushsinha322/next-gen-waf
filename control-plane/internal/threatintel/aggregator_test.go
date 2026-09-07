package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

// fakeStore captures upserts/purges so RefreshOnce can be tested without Postgres.
type fakeStore struct {
	mu       sync.Mutex
	upserted []db.IOC
	purges   int
}

func (f *fakeStore) UpsertIOCs(_ context.Context, iocs []db.IOC) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upserted = append(f.upserted, iocs...)
	return len(iocs), nil
}

func (f *fakeStore) PurgeExpiredIOCs(_ context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.purges++
	return 0, nil
}

func (f *fakeStore) find(typ, val string) (db.IOC, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, i := range f.upserted {
		if i.Type == typ && i.Value == val {
			return i, true
		}
	}
	return db.IOC{}, false
}

func serve(body string, status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestRefreshOnce_MergesStampsTTLAndDedupes(t *testing.T) {
	torSrv := serve("1.1.1.1\n5.5.5.5\n2.2.2.2\n", 200)
	defer torSrv.Close()
	feodoSrv := serve(`[{"ip_address":"5.5.5.5","malware":"Emotet"},{"ip_address":"9.9.9.9"}]`, 200)
	defer feodoSrv.Close()

	cfg := Config{
		Enabled:     true,
		Interval:    time.Hour,
		HTTPTimeout: 5 * time.Second,
		TorURL:      torSrv.URL,
		FeodoURL:    feodoSrv.URL,
		URLhausURL:  "off",
		STIXURL:     "off",
	}
	fs := &fakeStore{}
	agg := New(fs, cfg, zap.NewNop())

	n, err := agg.RefreshOnce(context.Background())
	if err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	// 4 unique IPs (5.5.5.5 deduped across tor+feodo) + the built-in UA seed.
	// Derived rather than hard-coded: this test is about cross-source dedupe, and
	// pinning the seed size made curating the UA list fail an unrelated test.
	builtin, err := builtinBadUserAgents()
	if err != nil {
		t.Fatal(err)
	}
	want := 4 + len(builtin)
	if n != want {
		t.Fatalf("want %d IOCs upserted (4 unique IPs + %d built-in UAs), got %d", want, len(builtin), n)
	}

	// Cross-source dedupe keeps the higher-confidence (feodo=90 > tor=60) entry.
	shared, ok := fs.find("ip", "5.5.5.5")
	if !ok {
		t.Fatal("5.5.5.5 missing")
	}
	if shared.Source != "feodo" || shared.Confidence != 90 {
		t.Errorf("want feodo/90 for shared IP, got %s/%d", shared.Source, shared.Confidence)
	}
	if shared.ExpiresAt == nil {
		t.Error("feed IOC must have a TTL (ExpiresAt)")
	}

	// Built-in UA IOCs are permanent (TTL 0 → no expiry).
	ua, ok := fs.find("user_agent", "sqlmap")
	if !ok {
		t.Fatal("builtin UA sqlmap missing")
	}
	if ua.ExpiresAt != nil {
		t.Error("builtin UA must not expire")
	}

	if fs.purges != 1 {
		t.Errorf("want 1 purge call, got %d", fs.purges)
	}
}

func TestRefreshOnce_ToleratesSourceFailure(t *testing.T) {
	torSrv := serve("7.7.7.7\n", 200)
	defer torSrv.Close()
	feodoSrv := serve("boom", 500) // fails
	defer feodoSrv.Close()

	cfg := Config{
		Enabled: true, Interval: time.Hour, HTTPTimeout: 5 * time.Second,
		TorURL: torSrv.URL, FeodoURL: feodoSrv.URL, URLhausURL: "off", STIXURL: "off",
	}
	fs := &fakeStore{}
	agg := New(fs, cfg, zap.NewNop())

	if _, err := agg.RefreshOnce(context.Background()); err != nil {
		t.Fatalf("a single source failure must not abort the refresh: %v", err)
	}
	if _, ok := fs.find("ip", "7.7.7.7"); !ok {
		t.Error("good source IOC must still be upserted")
	}
	if _, ok := fs.find("ip", "5.5.5.5"); ok {
		t.Error("failed source must contribute nothing")
	}
}

func TestRefreshOnce_AllSourcesFail(t *testing.T) {
	bad := serve("", 503)
	defer bad.Close()
	fs := &fakeStore{}
	agg := New(fs, Config{Enabled: true}, zap.NewNop())
	// Replace with only a failing source (no builtin safety net) to exercise the
	// all-failed path.
	agg.sources = []Source{{Name: "bad", URL: bad.URL, Parse: parseTorExitList}}

	if _, err := agg.RefreshOnce(context.Background()); err == nil {
		t.Fatal("want error when every source fails")
	}
}

func TestConfigSourcesDisable(t *testing.T) {
	cfg := Config{TorURL: "x", FeodoURL: "off", URLhausURL: "-", STIXURL: ""}
	names := map[string]bool{}
	for _, s := range cfg.Sources() {
		names[s.Name] = true
	}
	if !names["tor"] {
		t.Error("tor should be enabled")
	}
	if names["feodo"] || names["urlhaus"] || names["stix"] {
		t.Error("off/-/empty URLs must disable their sources")
	}
	if !names["builtin_bad_ua"] {
		t.Error("builtin UA provider is always enabled")
	}
}
