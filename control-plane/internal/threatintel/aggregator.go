package threatintel

import (
	"context"
	"fmt"
	"github.com/your-org/sentinel-waf/control-plane/internal/jobs"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

// maxFeedBytes caps a single feed response to protect the aggregator from a
// hostile or misconfigured upstream serving an unbounded body.
const maxFeedBytes = 64 << 20 // 64 MiB

// IOCStore is the slice of the DB store the aggregator needs. Declared as an
// interface so the aggregator is unit-testable with a fake (no live Postgres).
// *db.Store satisfies it.
type IOCStore interface {
	UpsertIOCs(ctx context.Context, iocs []db.IOC) (int, error)
	PurgeExpiredIOCs(ctx context.Context) (int64, error)
}

// Aggregator periodically fetches CTI feeds and syncs them into the IOC store.
type Aggregator struct {
	store    IOCStore
	client   *http.Client
	ua       string
	sources  []Source
	interval time.Duration
	log      *zap.Logger
	done     chan struct{}

	// configSource, when set, is consulted before every refresh so feed URLs,
	// the interval and the enabled flag edited on the Global Settings page take
	// effect without a restart. Enabled=false skips fetching but keeps the loop
	// (and the already-stored indicators) alive.
	mu           sync.Mutex
	configSource func() Config
	enabled      bool
	job          *jobs.Job
}

// SetConfigSource installs a function returning the desired Config; see the
// field comment. Safe to call before Start.
func (a *Aggregator) SetConfigSource(fn func() Config) { a.configSource = fn }

// reload applies the current configSource. Returns the (possibly new) interval.
func (a *Aggregator) reload() time.Duration {
	if a.configSource == nil {
		return a.interval
	}
	cfg := a.configSource()
	if cfg.Interval <= 0 {
		cfg.Interval = time.Hour
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	newNames := namesOf(cfg.Sources())
	oldNames := namesOf(a.sources)
	if newNames != oldNames || cfg.Interval != a.interval || cfg.Enabled != a.enabled {
		a.log.Info("threat-intel config applied", zap.Bool("enabled", cfg.Enabled),
			zap.Duration("interval", cfg.Interval), zap.String("sources", newNames))
	}
	a.sources = cfg.Sources()
	a.interval = cfg.Interval
	a.enabled = cfg.Enabled
	return a.interval
}

func namesOf(src []Source) string {
	names := make([]string, len(src))
	for i, s := range src {
		names[i] = s.Name
	}
	return strings.Join(names, ",")
}

// New builds an Aggregator from config. Defaults are applied for zero values.
func New(store IOCStore, cfg Config, log *zap.Logger) *Aggregator {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Hour
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 30 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "SentinelWAF-CTI/1.0"
	}
	a := &Aggregator{
		store:    store,
		client:   &http.Client{Timeout: cfg.HTTPTimeout},
		ua:       cfg.UserAgent,
		sources:  cfg.Sources(),
		interval: cfg.Interval,
		enabled:  true,
		log:      log,
		done:     make(chan struct{}),
	}
	a.job = jobs.Register("threat-intel.refresh",
		"Fetch every enabled indicator feed, merge into the corpus, purge expired indicators.",
		cfg.Interval, func(ctx context.Context) (string, error) {
			n, err := a.RefreshOnce(ctx)
			return fmt.Sprintf("%d indicators upserted", n), err
		})
	return a
}

// SourceNames lists the enabled feed names (for startup logging).
func (a *Aggregator) SourceNames() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	names := make([]string, len(a.sources))
	for i, s := range a.sources {
		names[i] = s.Name
	}
	return names
}

// Start runs an immediate refresh, then refreshes on the configured interval
// until Stop is called. Non-blocking.
func (a *Aggregator) Start(ctx context.Context) {
	if a.store == nil {
		a.log.Warn("threat-intel disabled — no database")
		return
	}
	go a.run(ctx)
	a.log.Info("threat-intel aggregator started",
		zap.Strings("sources", a.SourceNames()),
		zap.Duration("interval", a.interval))
}

// Stop halts the aggregator loop.
func (a *Aggregator) Stop() { close(a.done) }

func (a *Aggregator) run(ctx context.Context) {
	// Initial population shortly after boot (feeds can be slow; don't block).
	a.reload()
	a.refreshIfEnabled(ctx, "initial")

	// The ticker follows the operator-set interval: a console edit is applied on
	// the next tick, and the ticker is reset when the interval changed.
	interval := a.interval
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-a.done:
			return
		case <-ctx.Done():
			return
		case <-t.C:
			if ni := a.reload(); ni != interval {
				interval = ni
				t.Reset(interval)
			}
			a.refreshIfEnabled(ctx, "scheduled")
		}
	}
}

func (a *Aggregator) refreshIfEnabled(ctx context.Context, why string) {
	a.mu.Lock()
	enabled := a.enabled
	a.mu.Unlock()
	if !enabled {
		a.log.Info("threat-intel feed fetch skipped — disabled in settings", zap.String("run", why))
		a.job.Track(func() (string, error) { return "skipped — disabled in settings", nil })
		return
	}
	a.job.Track(func() (string, error) {
		n, err := a.RefreshOnce(ctx)
		if err != nil {
			a.log.Warn("threat-intel refresh failed", zap.Error(err), zap.String("run", why))
			return "", err
		}
		a.log.Info("threat-intel refresh complete", zap.Int("iocs", n), zap.String("run", why))
		return fmt.Sprintf("%d indicators upserted", n), nil
	})
}

// RefreshOnce fetches every enabled source concurrently, dedupes across sources,
// upserts the result, and purges expired IOCs. Returns the number of IOCs
// upserted. A single source failing is logged and skipped — it never aborts the
// others, so the WAF keeps enforcing the IOCs already in the DB.
func (a *Aggregator) RefreshOnce(ctx context.Context) (int, error) {
	now := time.Now()

	type result struct {
		src  Source
		iocs []db.IOC
		err  error
	}
	// Snapshot the source list: reload() may swap it from the run loop while a
	// caller-driven RefreshOnce is in flight.
	a.mu.Lock()
	sources := append([]Source(nil), a.sources...)
	a.mu.Unlock()
	results := make([]result, len(sources))
	var wg sync.WaitGroup
	for i, src := range sources {
		wg.Add(1)
		go func(i int, src Source) {
			defer wg.Done()
			iocs, err := a.fetchSource(ctx, src)
			results[i] = result{src: src, iocs: iocs, err: err}
		}(i, src)
	}
	wg.Wait()

	// Merge + dedupe across sources, keeping the highest-confidence occurrence
	// of each (type, value).
	merged := make(map[string]db.IOC)
	okSources := 0
	for _, r := range results {
		if r.err != nil {
			a.log.Warn("threat-intel source failed",
				zap.String("source", r.src.Name), zap.Error(r.err))
			continue
		}
		okSources++
		var exp *time.Time
		if r.src.TTL > 0 {
			e := now.Add(r.src.TTL)
			exp = &e
		}
		for _, ioc := range r.iocs {
			ioc.Source = r.src.Name
			if ioc.Category == "" {
				ioc.Category = r.src.Category
			}
			if ioc.Confidence == 0 {
				ioc.Confidence = r.src.Confidence
			}
			ioc.ExpiresAt = exp
			key := ioc.Type + "\x00" + ioc.Value
			if prev, ok := merged[key]; !ok || ioc.Confidence > prev.Confidence {
				merged[key] = ioc
			}
		}
	}

	if okSources == 0 {
		return 0, fmt.Errorf("all %d threat-intel sources failed", len(sources))
	}

	batch := make([]db.IOC, 0, len(merged))
	for _, ioc := range merged {
		batch = append(batch, ioc)
	}

	upserted, err := a.store.UpsertIOCs(ctx, batch)
	if err != nil {
		return upserted, fmt.Errorf("upsert IOCs: %w", err)
	}
	if purged, perr := a.store.PurgeExpiredIOCs(ctx); perr != nil {
		a.log.Warn("threat-intel purge failed", zap.Error(perr))
	} else if purged > 0 {
		a.log.Info("threat-intel purged expired IOCs", zap.Int64("removed", purged))
	}
	return upserted, nil
}

// fetchSource retrieves and parses one source. Static sources (Provider set) are
// produced locally; URL sources are fetched over HTTP.
func (a *Aggregator) fetchSource(ctx context.Context, src Source) ([]db.IOC, error) {
	if src.Provider != nil {
		return src.Provider()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", a.ua)
	req.Header.Set("Accept", "*/*")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", src.Name, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		return nil, fmt.Errorf("%s: read body: %w", src.Name, err)
	}
	if src.Parse == nil {
		return nil, fmt.Errorf("%s: no parser", src.Name)
	}
	return src.Parse(body)
}
