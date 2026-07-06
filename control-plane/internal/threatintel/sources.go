package threatintel

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

// Default upstream feeds. All are open, no-API-key sources. Any can be
// overridden or disabled via env (see ConfigFromEnv); set a URL to "off" or "-"
// to disable that feed while keeping the others.
const (
	defaultTorURL     = "https://check.torproject.org/torbulkexitlist"
	defaultFeodoURL   = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
	defaultURLhausURL = "https://urlhaus.abuse.ch/downloads/text/"
	// STIX/TAXII is opt-in (no universal free endpoint) — set SENTINEL_TI_STIX_URL
	// to a collection that serves a STIX 2.x bundle to enable it.
	defaultSTIXURL = ""
)

// Config controls the aggregator. Zero values are replaced with defaults in New.
type Config struct {
	Enabled     bool
	Interval    time.Duration
	HTTPTimeout time.Duration
	UserAgent   string

	TorURL     string
	FeodoURL   string
	URLhausURL string
	STIXURL    string
}

// Source is one feed: either fetched from URL and run through Parse, or produced
// locally by Provider (static seed lists). TTL sets each IOC's expiry — an IOC
// that drops out of the feed self-expires TTL after it was last seen. TTL == 0
// means no expiry (permanent, e.g. the built-in bad-UA seed).
type Source struct {
	Name       string
	URL        string
	Category   string
	Confidence int
	TTL        time.Duration
	Parse      func([]byte) ([]db.IOC, error)
	Provider   func() ([]db.IOC, error)
}

// ConfigFromEnv reads aggregator settings from the environment.
func ConfigFromEnv() Config {
	return Config{
		Enabled:     envBool("SENTINEL_THREATINTEL_ENABLED", true),
		Interval:    envDuration("SENTINEL_THREATINTEL_INTERVAL", time.Hour),
		HTTPTimeout: envDuration("SENTINEL_THREATINTEL_HTTP_TIMEOUT", 30*time.Second),
		UserAgent:   envOr("SENTINEL_THREATINTEL_USER_AGENT", "SentinelWAF-CTI/1.0"),
		TorURL:      envOr("SENTINEL_TI_TOR_URL", defaultTorURL),
		FeodoURL:    envOr("SENTINEL_TI_FEODO_URL", defaultFeodoURL),
		URLhausURL:  envOr("SENTINEL_TI_URLHAUS_URL", defaultURLhausURL),
		STIXURL:     envOr("SENTINEL_TI_STIX_URL", defaultSTIXURL),
	}
}

// Sources builds the enabled feed list from the config. A source with a blank or
// "off"/"-" URL is skipped (except static providers, which have no URL).
func (c Config) Sources() []Source {
	all := []Source{
		{Name: "tor", URL: c.TorURL, Category: "tor_exit", Confidence: 60, TTL: 24 * time.Hour, Parse: parseTorExitList},
		{Name: "feodo", URL: c.FeodoURL, Category: "malware_c2", Confidence: 90, TTL: 24 * time.Hour, Parse: parseFeodoJSON},
		{Name: "urlhaus", URL: c.URLhausURL, Category: "malware_distribution", Confidence: 80, TTL: 24 * time.Hour, Parse: parseURLhausText},
		{Name: "stix", URL: c.STIXURL, Category: "stix_indicator", Confidence: 70, TTL: 7 * 24 * time.Hour, Parse: parseSTIXBundle},
		// Built-in seed of well-known malicious/scanner user agents. No expiry;
		// refreshed every cycle so it survives a manual DB purge.
		{Name: "builtin_bad_ua", Category: "scanner", Confidence: 85, TTL: 0, Provider: builtinBadUserAgents},
	}
	out := make([]Source, 0, len(all))
	for _, s := range all {
		if s.Provider == nil && urlDisabled(s.URL) {
			continue
		}
		out = append(out, s)
	}
	return out
}

func urlDisabled(u string) bool {
	u = strings.TrimSpace(strings.ToLower(u))
	return u == "" || u == "off" || u == "-" || u == "disabled"
}

// builtinBadUserAgents is a curated seed of scanner/exploit-tool User-Agents.
// These are exact-match IOCs (Type user_agent). Kept small and high-signal —
// broad UA blocklists cause false positives.
func builtinBadUserAgents() ([]db.IOC, error) {
	uas := []string{
		"sqlmap",
		"nikto",
		"nmap",
		"masscan",
		"nessus",
		"acunetix",
		"nuclei",
		"dirbuster",
		"gobuster",
		"wpscan",
		"hydra",
		"havij",
		"zgrab",
		"zmeu",
		"fimap",
		"jaeles",
		"feroxbuster",
		"whatweb",
		"arachni",
	}
	out := make([]db.IOC, 0, len(uas))
	for _, ua := range uas {
		out = append(out, db.IOC{Type: "user_agent", Value: ua})
	}
	return out, nil
}

// --- env helpers ---

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}
