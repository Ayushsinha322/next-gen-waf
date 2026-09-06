// Package geoipfetch keeps a country GeoIP database on disk for the data planes.
//
// Country filtering was inert on every deployment to date because no database
// ever shipped: MaxMind's licence forbids redistributing GeoLite2. DB-IP's
// "IP to Country Lite" database is CC BY 4.0 — redistributable with
// attribution — and is published monthly at a predictable URL. This job
// downloads it into the directory every data plane mounts, and the data plane's
// watcher opens it within a minute. Attribution ("IP Geolocation by DB-IP") is
// shown in the console wherever the data is used.
package geoipfetch

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/your-org/sentinel-waf/control-plane/internal/jobs"
)

// FileName is what the data planes look for (SENTINEL_GEOIP_DB defaults to it).
const FileName = "dbip-country-lite.mmdb"

// DefaultURL is DB-IP's monthly free country database; {YYYY} and {MM} are
// substituted for the current month, and the previous month is tried when the
// current one is not published yet.
const DefaultURL = "https://download.db-ip.com/free/dbip-country-lite-{YYYY}-{MM}.mmdb.gz"

// Config is re-read from the settings source on every tick.
type Config struct {
	Enabled bool
	URL     string
	// MaxAge: skip the download when the file on disk is younger than this.
	MaxAge time.Duration
}

// Fetcher owns the job. Dir is where the database is written (empty disables).
type Fetcher struct {
	dir          string
	client       *http.Client
	log          *zap.Logger
	configSource func() Config
	job          *jobs.Job
	done         chan struct{}
}

func New(dir string, configSource func() Config, log *zap.Logger) *Fetcher {
	f := &Fetcher{
		dir:          dir,
		client:       &http.Client{Timeout: 5 * time.Minute},
		log:          log,
		configSource: configSource,
		done:         make(chan struct{}),
	}
	f.job = jobs.Register("geoip.refresh",
		"Download the monthly DB-IP country database (CC BY 4.0) into the directory every data plane mounts, so country rules can enforce.",
		24*time.Hour, func(ctx context.Context) (string, error) { return f.RefreshOnce(ctx, true) })
	return f
}

// Start runs one refresh shortly after boot and then daily. The job itself
// decides whether a download is due, so the daily tick is cheap.
func (f *Fetcher) Start() {
	if f.dir == "" {
		f.log.Info("geoip fetcher disabled — SENTINEL_GEOIP_DIR not set")
		return
	}
	go func() {
		f.tick()
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-f.done:
				return
			case <-t.C:
				f.tick()
			}
		}
	}()
}

func (f *Fetcher) Stop() { close(f.done) }

func (f *Fetcher) tick() {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	f.job.Track(func() (string, error) { return f.RefreshOnce(ctx, false) })
}

// RefreshOnce downloads when enabled and due (or forced), writing atomically.
func (f *Fetcher) RefreshOnce(ctx context.Context, force bool) (string, error) {
	cfg := Config{Enabled: true, URL: DefaultURL, MaxAge: 7 * 24 * time.Hour}
	if f.configSource != nil {
		cfg = f.configSource()
	}
	if f.dir == "" {
		return "skipped — no GeoIP directory configured (SENTINEL_GEOIP_DIR)", nil
	}
	if !cfg.Enabled && !force {
		return "skipped — geoip.auto_fetch is off", nil
	}
	target := filepath.Join(f.dir, FileName)
	if !force {
		if st, err := os.Stat(target); err == nil && time.Since(st.ModTime()) < cfg.MaxAge {
			return fmt.Sprintf("up to date — %s is %s old", FileName, time.Since(st.ModTime()).Round(time.Hour)), nil
		}
	}
	now := time.Now().UTC()
	var lastErr error
	for _, when := range []time.Time{now, now.AddDate(0, -1, 0)} {
		url := ExpandURL(cfg.URL, when)
		n, err := f.download(ctx, url, target)
		if err == nil {
			return fmt.Sprintf("downloaded %s (%d bytes) from %s", FileName, n, url), nil
		}
		lastErr = err
		f.log.Warn("geoip download failed", zap.String("url", url), zap.Error(err))
	}
	return "", lastErr
}

// ExpandURL substitutes {YYYY} and {MM} for the given month.
func ExpandURL(tmpl string, t time.Time) string {
	return strings.NewReplacer("{YYYY}", fmt.Sprintf("%04d", t.Year()), "{MM}", fmt.Sprintf("%02d", int(t.Month()))).Replace(tmpl)
}

// download fetches url, gunzips when the name says so, validates the MMDB
// trailer, and renames into place so a reader never sees a partial file.
func (f *Fetcher) download(ctx context.Context, url, target string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "SentinelWAF-GeoIP/1.0 (+https://db-ip.com attribution)")
	resp, err := f.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %s", resp.Status)
	}
	if err := os.MkdirAll(f.dir, 0o755); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(f.dir, ".geoip-*.tmp")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	var src io.Reader = io.LimitReader(resp.Body, 512<<20)
	if strings.HasSuffix(url, ".gz") {
		gz, err := gzip.NewReader(src)
		if err != nil {
			tmp.Close()
			return 0, fmt.Errorf("gunzip: %w", err)
		}
		defer gz.Close()
		src = gz
	}
	n, err := io.Copy(tmp, src)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, err
	}
	if err := ValidateMMDB(tmpName); err != nil {
		return 0, err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return 0, err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return 0, err
	}
	return n, nil
}

// ValidateMMDB checks the MaxMind DB metadata marker is present near the end
// of the file, so a captive-portal HTML page or a truncated download is never
// installed as a database.
func ValidateMMDB(path string) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return err
	}
	if st.Size() < 1024 {
		return fmt.Errorf("file too small to be an MMDB (%d bytes)", st.Size())
	}
	// The metadata section starts with "\xab\xcd\xefMaxMind.com" in the last 128 KiB.
	tail := int64(128 << 10)
	if tail > st.Size() {
		tail = st.Size()
	}
	buf := make([]byte, tail)
	if _, err := fh.ReadAt(buf, st.Size()-tail); err != nil && err != io.EOF {
		return err
	}
	if !strings.Contains(string(buf), "\xab\xcd\xefMaxMind.com") {
		return fmt.Errorf("not an MMDB file (no MaxMind metadata marker)")
	}
	return nil
}
