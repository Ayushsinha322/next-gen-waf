// Package clickhouse is a minimal read-only ClickHouse HTTP client used by the
// control plane to serve searchable WAF history (the proxy is the writer; the
// control plane is the reader). Stdlib-only.
package clickhouse

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"
)

// Client talks to ClickHouse over its HTTP interface.
type Client struct {
	url      string
	db       string
	user     string
	password string
	http     *http.Client
	enabled  bool
}

// FromEnv builds a client from SENTINEL_CLICKHOUSE_* env vars. The URL may be a
// bare endpoint (http://host:8123) or a combined form with embedded credentials
// and database path (http://user:pass@host:8123/dbname) — both are parsed.
// Separate SENTINEL_CLICKHOUSE_{DB,USER,PASSWORD} vars take precedence when set.
// When the URL is unset the client is disabled and queries return a "not
// configured" error so the UI can show an honest empty state.
func FromEnv() *Client {
	raw := strings.TrimSpace(getenv("SENTINEL_CLICKHOUSE_URL", ""))
	c := &Client{
		db:       getenv("SENTINEL_CLICKHOUSE_DB", "sentinel_logs"),
		user:     getenv("SENTINEL_CLICKHOUSE_USER", "sentinel"),
		password: getenv("SENTINEL_CLICKHOUSE_PASSWORD", "sentinel_dev"),
		http:     &http.Client{Timeout: 10 * time.Second},
	}
	if raw == "" {
		return c // disabled
	}
	if u, err := neturl.Parse(raw); err == nil && u.Host != "" {
		c.url = u.Scheme + "://" + u.Host
		// Credentials embedded in the URL fill in only when not set explicitly.
		if u.User != nil {
			if os.Getenv("SENTINEL_CLICKHOUSE_USER") == "" {
				c.user = u.User.Username()
			}
			if pw, ok := u.User.Password(); ok && os.Getenv("SENTINEL_CLICKHOUSE_PASSWORD") == "" {
				c.password = pw
			}
		}
		if p := strings.Trim(u.Path, "/"); p != "" && os.Getenv("SENTINEL_CLICKHOUSE_DB") == "" {
			c.db = p
		}
	} else {
		c.url = strings.TrimRight(raw, "/")
	}
	c.enabled = c.url != ""
	return c
}

func (c *Client) Enabled() bool { return c.enabled }

// ErrDisabled is returned when ClickHouse is not configured.
var ErrDisabled = fmt.Errorf("clickhouse not configured (set SENTINEL_CLICKHOUSE_URL)")

// query POSTs raw SQL and returns the response body. Callers append FORMAT.
func (c *Client) query(ctx context.Context, sql string) ([]byte, error) {
	if !c.enabled {
		return nil, ErrDisabled
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, strings.NewReader(sql))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	if c.user != "" {
		req.Header.Set("X-ClickHouse-User", c.user)
	}
	if c.password != "" {
		req.Header.Set("X-ClickHouse-Key", c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("clickhouse HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// jsonEnvelope is the shape of ClickHouse `FORMAT JSON` responses.
type jsonEnvelope struct {
	Data json.RawMessage `json:"data"`
	Rows int             `json:"rows"`
}

// queryJSON runs `sql` with FORMAT JSON and unmarshals the data array into dst.
func (c *Client) queryJSON(ctx context.Context, sql string, dst any) error {
	body, err := c.query(ctx,
		sql+" SETTINGS output_format_json_quote_64bit_integers = 0 FORMAT JSON")
	if err != nil {
		return err
	}
	var env jsonEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("parse clickhouse response: %w", err)
	}
	return json.Unmarshal(env.Data, dst)
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Event struct {
	TS       int64  `json:"ts"`
	IP       string `json:"ip"`
	Country  string `json:"country"`
	Site     string `json:"site"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Rule     string `json:"rule"`
	Attack   string `json:"attack"`
	Action   string `json:"action"`
	Severity string `json:"severity"`
	Score    int    `json:"score"`
	Status   int    `json:"status"`
	Protocol string `json:"protocol"`
	// Written since the explain-the-verdict change. Old rows have them empty,
	// which the UI renders as absent rather than fabricating an explanation.
	RequestID   string `json:"request_id"`
	Target      string `json:"target"`
	Mode        string `json:"mode"`
	Threshold   int    `json:"threshold"`
	Explanation string `json:"explanation"`
}

type TimelineBucket struct {
	TS      int64 `json:"ts"`
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
}

// SeverityBucket is one time bucket of the threat-detection trend, split by
// severity band. High folds CRITICAL + HIGH together so the chart reads at a
// glance (matches the four-line High/Medium/Low/Info legend in the UI).
type SeverityBucket struct {
	TS     int64 `json:"ts"`
	High   int64 `json:"high"`
	Medium int64 `json:"medium"`
	Low    int64 `json:"low"`
	Info   int64 `json:"info"`
}

type Facet struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// Attacker is one source IP rolled up over the query window: how many WAF events
// it generated (requests), how many were actively blocked (blocked), its
// resolved country (best-effort — empty until GeoIP tags it), and when it was
// last seen. Drives the "Top Attacker IPs" overview card.
type Attacker struct {
	IP       string `json:"ip"`
	Country  string `json:"country"`
	Requests int64  `json:"requests"`
	Blocked  int64  `json:"blocked"`
	LastSeen int64  `json:"last_seen"`
}

// SearchFilter holds the (already-untrusted) search parameters.
type SearchFilter struct {
	// Tenant scopes the query to one tenant's events. It is the security
	// boundary for Threat Search and is always applied by searchWhere.
	Tenant                                           string
	Site, Country, Rule, Action, IP, Protocol, Query string
	From, To                                         int64
	Limit                                            int
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

// Status reports reachability + table row counts (for the UI empty state).
// DiskUsage returns the used fraction (0..1) of the disk(s) ClickHouse stores
// its data on, plus free/total bytes, by summing system.disks. The disk-pressure
// monitor uses this to page the SOC before the event store fills up (a full
// ClickHouse degrades Threat Search, not the WAF, but must never fill silently).
func (c *Client) DiskUsage(ctx context.Context) (usedFrac float64, freeBytes, totalBytes int64, err error) {
	if !c.enabled {
		return 0, 0, 0, fmt.Errorf("clickhouse not configured")
	}
	var rows []struct {
		Free  int64 `json:"free"`
		Total int64 `json:"total"`
	}
	if err := c.queryJSON(ctx,
		"SELECT toInt64(sum(free_space)) AS free, toInt64(sum(total_space)) AS total FROM system.disks", &rows); err != nil {
		return 0, 0, 0, err
	}
	if len(rows) == 0 || rows[0].Total <= 0 {
		return 0, 0, 0, fmt.Errorf("clickhouse: no disk rows from system.disks")
	}
	free, total := rows[0].Free, rows[0].Total
	return 1 - float64(free)/float64(total), free, total, nil
}

func (c *Client) Status(ctx context.Context, tenant string) (map[string]any, error) {
	if !c.enabled {
		return map[string]any{"configured": false, "reachable": false}, nil
	}
	var rows []struct {
		Events  int64 `json:"events"`
		Traffic int64 `json:"traffic"`
	}
	// Both counts are tenant-scoped now (traffic_buckets gained a tenant column).
	err := c.queryJSON(ctx, fmt.Sprintf(
		"SELECT (SELECT count() FROM %s.waf_events WHERE tenant = '%s') AS events, "+
			"(SELECT count() FROM %s.traffic_buckets WHERE tenant = '%s') AS traffic",
		c.db, esc(tenant), c.db, esc(tenant)), &rows)
	if err != nil {
		return map[string]any{"configured": true, "reachable": false, "error": err.Error()}, nil
	}
	out := map[string]any{"configured": true, "reachable": true}
	if len(rows) > 0 {
		out["events"] = rows[0].Events
		out["traffic_buckets"] = rows[0].Traffic
	}
	return out, nil
}

// Search returns matching waf_events, newest first.
// searchWhere builds the WHERE clauses for a Threat Search query. The tenant
// predicate is ALWAYS included first — it is the cross-tenant isolation
// boundary — so no code path can accidentally query another tenant's events.
func (c *Client) searchWhere(f SearchFilter) []string {
	where := c.timeWhere(f.From, f.To)
	where = append(where, eq("tenant", f.Tenant))
	if f.Site != "" {
		where = append(where, eq("site", f.Site))
	}
	if f.Country != "" {
		where = append(where, eq("country", strings.ToUpper(f.Country)))
	}
	if f.Rule != "" {
		where = append(where, eq("rule", f.Rule))
	}
	if f.Action != "" {
		where = append(where, eq("action", strings.ToUpper(f.Action)))
	}
	if f.IP != "" {
		where = append(where, eq("ip", f.IP))
	}
	if f.Protocol != "" {
		where = append(where, eq("protocol", strings.ToLower(f.Protocol)))
	}
	if f.Query != "" {
		// substring match across path / attack / rule
		q := esc(f.Query)
		where = append(where, fmt.Sprintf(
			"(positionCaseInsensitive(path, '%s') > 0 OR positionCaseInsensitive(attack, '%s') > 0 "+
				"OR positionCaseInsensitive(explanation, '%s') > 0 OR rule = '%s')",
			q, q, q, q))
	}
	return where
}

func (c *Client) Search(ctx context.Context, f SearchFilter) ([]Event, error) {
	where := c.searchWhere(f)
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	sql := fmt.Sprintf(
		"SELECT toUnixTimestamp(ts) AS ts, ip, country, site, method, path, rule, attack, action, severity, score, status, protocol, "+
			"request_id, target, mode, threshold, explanation "+
			"FROM %s.waf_events WHERE %s ORDER BY ts DESC LIMIT %d",
		c.db, strings.Join(where, " AND "), limit)
	var out []Event
	if err := c.queryJSON(ctx, sql, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Timeline returns per-bucket total/blocked counts from traffic_buckets,
// scoped to the given tenant.
func (c *Client) Timeline(ctx context.Context, tenant string, from, to int64, bucketSecs int) ([]TimelineBucket, error) {
	if bucketSecs <= 0 {
		bucketSecs = 60
	}
	where := append(c.timeWhere(from, to), eq("tenant", tenant))
	sql := fmt.Sprintf(
		"SELECT toUnixTimestamp(toStartOfInterval(ts, INTERVAL %d SECOND)) AS ts, "+
			"sum(reqs) AS total, sum(blocked) AS blocked "+
			"FROM %s.traffic_buckets WHERE %s "+
			"GROUP BY ts ORDER BY ts",
		bucketSecs, c.db, strings.Join(where, " AND "))
	var out []TimelineBucket
	if err := c.queryJSON(ctx, sql, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SeverityTimeline buckets waf_events by time and severity band for the threat
// detection trend chart. High folds CRITICAL + HIGH together. Tenant-scoped
// (isolation boundary), like Timeline/Facets. Severity match is case-insensitive.
func (c *Client) SeverityTimeline(ctx context.Context, tenant string, from, to int64, bucketSecs int) ([]SeverityBucket, error) {
	if bucketSecs <= 0 {
		bucketSecs = 60
	}
	where := append(c.timeWhere(from, to), eq("tenant", tenant))
	sql := fmt.Sprintf(
		"SELECT toUnixTimestamp(toStartOfInterval(ts, INTERVAL %d SECOND)) AS ts, "+
			"countIf(upper(severity) IN ('CRITICAL','HIGH')) AS high, "+
			"countIf(upper(severity) = 'MEDIUM') AS medium, "+
			"countIf(upper(severity) = 'LOW') AS low, "+
			"countIf(upper(severity) = 'INFO') AS info "+
			"FROM %s.waf_events WHERE %s "+
			"GROUP BY ts ORDER BY ts",
		bucketSecs, c.db, strings.Join(where, " AND "))
	var out []SeverityBucket
	if err := c.queryJSON(ctx, sql, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Facets returns top values for a column (rule|ip|country|action|site).
func (c *Client) Facets(ctx context.Context, column, tenant string, from, to int64, limit int) ([]Facet, error) {
	col, ok := facetColumn(column)
	if !ok {
		return nil, fmt.Errorf("invalid facet column %q", column)
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	// Tenant-scoped (isolation boundary), like Search.
	where := append(c.timeWhere(from, to), eq("tenant", tenant))
	sql := fmt.Sprintf(
		"SELECT %s AS key, count() AS count FROM %s.waf_events WHERE %s AND %s != '' "+
			"GROUP BY key ORDER BY count DESC LIMIT %d",
		col, c.db, strings.Join(where, " AND "), col, limit)
	var out []Facet
	if err := c.queryJSON(ctx, sql, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// TopAttackers rolls up waf_events by source IP over the window, returning the
// busiest IPs with their total event count, actively-blocked count, resolved
// country (best-effort — the most recent non-empty value), and last-seen time.
// Tenant-scoped like Search/Facets — the cross-tenant isolation boundary — so
// no path can surface another tenant's attackers. Ordered by total events then
// blocks descending.
func (c *Client) TopAttackers(ctx context.Context, tenant string, from, to int64, limit int) ([]Attacker, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	where := append(c.timeWhere(from, to), eq("tenant", tenant))
	// argMax(country, ts) picks the country from this IP's most recent event so a
	// single stale/empty tag can't win; anyIf would ignore recency. Empty codes
	// simply lose to any tagged row, and the client renders a neutral globe.
	sql := fmt.Sprintf(
		"SELECT ip AS ip, argMax(country, ts) AS country, "+
			"count() AS requests, countIf(action = 'BLOCK') AS blocked, "+
			"toUnixTimestamp(max(ts)) AS last_seen "+
			"FROM %s.waf_events WHERE %s AND ip != '' "+
			"GROUP BY ip ORDER BY requests DESC, blocked DESC LIMIT %d",
		c.db, strings.Join(where, " AND "), limit)
	var out []Attacker
	if err := c.queryJSON(ctx, sql, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RecentThreatIntelBlocks returns the newest threat-intel-driven blocks visible
// to a tenant (events the data plane tagged rule="THREATINTEL"; the human reason
// is in the `attack` column). The IOC corpus is node-global and enforced BEFORE
// site matching, so most TI blocks carry an empty tenant/site: those are
// node-global threat events and are surfaced to every tenant. Rows that DID match
// a site carry that site's tenant and stay private to it. So the predicate is
// (tenant = caller OR tenant is empty): the caller's own TI blocks plus node-global
// ones, but never another tenant's site-attributed traffic. Pass the caller's
// tenant from the JWT, never client input.
// Returns empty when ClickHouse is disabled at the handler layer.
func (c *Client) RecentThreatIntelBlocks(ctx context.Context, tenant string, from, to int64, limit int) ([]Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	where := c.timeWhere(from, to)
	// Node-global TI blocks (tenant='') are shown to all tenants; site-attributed
	// ones only to their owner. eq() escapes the caller tenant; '' is a constant.
	where = append(where, "("+eq("tenant", tenant)+" OR tenant = '')")
	where = append(where, "rule = 'THREATINTEL'") // constant literal — no injection surface
	sql := fmt.Sprintf(
		"SELECT toUnixTimestamp(ts) AS ts, ip, country, site, method, path, rule, attack, action, severity, score, status, protocol "+
			"FROM %s.waf_events WHERE %s ORDER BY ts DESC LIMIT %d",
		c.db, strings.Join(where, " AND "), limit)
	var out []Event
	if err := c.queryJSON(ctx, sql, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (c *Client) timeWhere(from, to int64) []string {
	if from <= 0 {
		from = time.Now().Add(-24 * time.Hour).Unix()
	}
	if to <= 0 {
		to = time.Now().Add(time.Hour).Unix()
	}
	return []string{fmt.Sprintf("ts >= toDateTime(%d) AND ts <= toDateTime(%d)", from, to)}
}

// facetColumn whitelists groupable columns (prevents SQL injection via column).
func facetColumn(c string) (string, bool) {
	switch strings.ToLower(c) {
	case "rule", "ip", "country", "action", "site", "severity", "protocol":
		return strings.ToLower(c), true
	}
	return "", false
}

// eq builds a "col = 'val'" predicate. col MUST be a trusted/whitelisted column
// name (see facetColumn); only val is escaped.
func eq(col, val string) string { return fmt.Sprintf("%s = '%s'", col, esc(val)) }

// esc renders a user value safe inside a single-quoted ClickHouse string
// literal. ClickHouse's HTTP interface on this path has no bind-parameter
// support, so injection-safety rests on three invariants, all upheld here:
//   - every user-supplied value passes through esc(),
//   - column/table names are whitelisted (facetColumn) — never interpolated raw,
//   - numeric bounds (from/to/limit/bucket) are formatted with %d.
//
// Backslash is escaped before the quote so the quote-escape can't be undone.
func esc(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\") // must run first
	s = strings.ReplaceAll(s, "'", "\\'")
	s = strings.ReplaceAll(s, "\x00", "") // defensive: drop embedded NULs
	return s
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
