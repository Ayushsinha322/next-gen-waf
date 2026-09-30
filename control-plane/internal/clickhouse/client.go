// Package clickhouse is a minimal read-only ClickHouse HTTP client used by the
// control plane to serve searchable WAF history (the proxy is the writer; the
// control plane is the reader). Stdlib-only.
package clickhouse

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"
)

// httpClientForCA returns an HTTP client that trusts the private CA named by
// SENTINEL_CLICKHOUSE_CA_FILE, mirroring the Rust writer in
// crates/sentinel-storage/src/clickhouse.rs.
//
// Needed because in the 2-VM topology ClickHouse lives only on the active node,
// so the passive node's control plane READS across the peer link. Go's default
// transport speaks HTTPS but trusts only the system roots, and the deployment's
// ClickHouse cert is issued by its own internal CA — so without this, switching
// the URL to https:// turns every Threat Search query into a verification error.
//
// Deliberately does NOT use SSL_CERT_FILE to inject the CA globally: that
// REPLACES the system pool for the whole process, which would break outbound
// HTTPS to public endpoints (threat-intel feeds) as a side effect of securing
// one internal hop. Scope the trust to this client instead.
//
// A configured-but-unusable CA file is fatal to TLS rather than a silent
// downgrade to the system pool — same rule as the Rust side. Widening trust
// because a path was wrong is the wrong failure for a WAF.
func httpClientForCA() *http.Client {
	c := &http.Client{Timeout: 10 * time.Second}
	path := strings.TrimSpace(os.Getenv("SENTINEL_CLICKHOUSE_CA_FILE"))
	if path == "" {
		return c
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[sentinel] clickhouse TLS: cannot read SENTINEL_CLICKHOUSE_CA_FILE %q: %v "+
			"— refusing to fall back to system roots; https queries will FAIL", path, err)
		pem = nil
	}
	pool := x509.NewCertPool()
	if len(pem) > 0 && !pool.AppendCertsFromPEM(pem) {
		log.Printf("[sentinel] clickhouse TLS: %q contained no usable certificates "+
			"— refusing to fall back to system roots; https queries will FAIL", path)
	}
	// An empty pool trusts nothing, so verification fails loudly and visibly.
	c.Transport = &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}}
	return c
}

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
		http:     httpClientForCA(),
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
	TS      int64  `json:"ts"`
	IP      string `json:"ip"`
	Country string `json:"country"`
	Site    string `json:"site"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	// Forensic-triage fields (2026-08): the query string, the page the request
	// was fired from, and the text the rule matched (credential targets are
	// redacted by the data plane before the row is ever written). Empty on rows
	// that predate the columns — the UI renders that as absent.
	Query    string `json:"query"`
	Referer  string `json:"referer"`
	Matched  string `json:"matched"`
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
	// JA4 TLS fingerprint of the client (t… TCP, q… QUIC), empty for plaintext
	// or rows stored before it was recorded. The value that drove the
	// malicious-JA4 bot signal and the JA4 blocklist — without it, a block it
	// caused could not be explained from the row.
	JA4 string `json:"ja4"`
	// Every rule that contributed to the verdict (array of {id, msg, sev,
	// score, target, matched}, biggest score first), the redacted request
	// headers (object), and the User-Agent. Written by the data plane since
	// 2026-09-25; absent on older rows, which the UI renders as absent.
	Rules   JSONText `json:"rules,omitempty"`
	Headers JSONText `json:"headers,omitempty"`
	UA      string   `json:"ua"`
}

// JSONText is a ClickHouse String column that holds JSON text. ClickHouse
// returns it as a JSON *string*; this decodes that string and re-encodes the
// JSON it contains, so the console receives an array/object rather than
// escaped text. Empty or invalid text decodes to nothing and is omitted.
type JSONText []byte

func (j *JSONText) UnmarshalJSON(b []byte) error {
	var text string
	if err := json.Unmarshal(b, &text); err != nil {
		// Already JSON rather than a string (a future column type): keep it.
		if json.Valid(b) && string(b) != "null" {
			*j = append((*j)[:0], b...)
		} else {
			*j = nil
		}
		return nil
	}
	if text == "" || !json.Valid([]byte(text)) {
		*j = nil
		return nil
	}
	*j = JSONText(text)
	return nil
}

func (j JSONText) MarshalJSON() ([]byte, error) {
	if len(j) == 0 {
		return []byte("null"), nil
	}
	return []byte(j), nil
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
	// Label names a rule facet's key: the attack message it most recently
	// recorded ("9900100" → "SQL Injection via libinjection"). A bare rule id
	// told an operator nothing without a second lookup. Empty for other columns.
	Label string `json:"label,omitempty"`
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
	Tenant                                                     string
	Site, Country, Rule, Action, IP, Protocol, Severity, Query string
	From, To                                                   int64
	Limit                                                      int
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
	if f.Severity != "" {
		// Compared upper-cased on both sides: the data plane has written mixed
		// case over the life of the table, so a literal match would drop rows.
		where = append(where, fmt.Sprintf("upper(severity) = '%s'", esc(strings.ToUpper(f.Severity))))
	}
	if f.Query != "" {
		// Substring match across path / attack / rule, plus an exact match on
		// request_id.
		//
		// request_id is here because it is the Support ID printed on the block
		// page: a customer calls quoting one string, and the operator pastes it
		// into this box expecting the request. Without this clause the id is
		// stored on every row and findable by nothing, which makes the whole
		// support path decorative. Exact match rather than substring — an id is
		// either the one you want or it is not, and a substring scan over a
		// high-cardinality column is the expensive way to learn that.
		q := esc(f.Query)
		// query and matched are searched too: "find every event containing
		// UNION SELECT" is the canonical SOC hunt, and the payload lives in
		// those two columns, not in path.
		where = append(where, fmt.Sprintf(
			"(positionCaseInsensitive(path, '%s') > 0 OR positionCaseInsensitive(attack, '%s') > 0 "+
				"OR positionCaseInsensitive(explanation, '%s') > 0 "+
				"OR positionCaseInsensitive(query, '%s') > 0 OR positionCaseInsensitive(matched, '%s') > 0 "+
				"OR rule = '%s' OR request_id = '%s' OR ja4 = '%s')",
			q, q, q, q, q, q, q, q))
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
		"SELECT toUnixTimestamp(ts) AS ts, ip, country, site, method, path, query, referer, matched, "+
			"rule, attack, action, severity, score, status, protocol, "+
			"request_id, target, mode, threshold, explanation, ja4, rules, headers, ua "+
			"FROM %s.waf_events WHERE %s ORDER BY ts DESC LIMIT %d",
		c.db, strings.Join(where, " AND "), limit)
	var out []Event
	if err := c.queryJSON(ctx, sql, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// FindBySupportID resolves the Support ID printed on a block page back to the
// request that produced it.
//
// Deliberately NOT time-bounded, unlike every other query here. A customer
// rings on Thursday about a block that happened on Monday, and the operator has
// whatever range the UI last had selected — usually 24 hours. Applying that
// window would return nothing and read as "no such request", which is the exact
// failure this feature exists to prevent. Retention already bounds how far back
// this can reach; the id is a UUID, so the match is a point lookup either way.
//
// Still tenant-scoped: the id is quoted by a caller over the phone and must not
// be usable to read another tenant's event.
func (c *Client) FindBySupportID(ctx context.Context, tenant, supportID string) ([]Event, error) {
	id := strings.TrimSpace(supportID)
	if id == "" {
		return []Event{}, nil
	}
	sql := fmt.Sprintf(
		"SELECT toUnixTimestamp(ts) AS ts, ip, country, site, method, path, query, referer, matched, "+
			"rule, attack, action, severity, score, status, protocol, "+
			"request_id, target, mode, threshold, explanation, ja4, rules, headers, ua "+
			"FROM %s.waf_events WHERE %s AND %s ORDER BY ts DESC LIMIT 25",
		c.db, eq("tenant", tenant), eq("request_id", id))
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

// Facets returns top values for a column (see facetColumn).
func (c *Client) Facets(ctx context.Context, column, tenant string, from, to int64, limit int) ([]Facet, error) {
	sql, err := c.facetSQL(column, tenant, from, to, limit)
	if err != nil {
		return nil, err
	}
	var out []Facet
	if err := c.queryJSON(ctx, sql, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RuleHit is how often one rule fired over a window, and how often the
// request was actually blocked (a rule can fire in learning mode or below the
// anomaly threshold without a block).
type RuleHit struct {
	RuleID  string `json:"rule_id"`
	Count   int64  `json:"count"`
	Blocked int64  `json:"blocked"`
}

// RuleHits rolls up waf_events by rule id over the window. It feeds the Rules
// page's compiled-rule inventory, so an operator can see which of the few
// hundred CRS rules actually do work on this deployment. Tenant-scoped like
// every other read here.
func (c *Client) RuleHits(ctx context.Context, tenant string, from, to int64) ([]RuleHit, error) {
	where := append(c.timeWhere(from, to), eq("tenant", tenant))
	sql := fmt.Sprintf(
		"SELECT rule AS rule_id, count() AS count, countIf(action = 'BLOCK') AS blocked "+
			"FROM %s.waf_events WHERE %s AND rule != '' "+
			"GROUP BY rule ORDER BY count DESC LIMIT 5000",
		c.db, strings.Join(where, " AND "))
	var out []RuleHit
	if err := c.queryJSON(ctx, sql, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// LearningStat is one rule's would-have-blocked aggregate, reconstructed from
// the stored DETECT events. Field names match logs.LearningStat so the two
// sources are interchangeable to an API consumer.
type LearningStat struct {
	RuleID   string   `json:"rule_id"`
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Message  string   `json:"message"`
	Count    int64    `json:"count"`
	LastSeen string   `json:"last_seen"`
	Samples  []string `json:"samples"`
}

// LearningStats rebuilds the learning report from stored events rather than
// from process memory.
//
// The in-memory aggregate in logs.Hub is fed by TAILING waf.log from its end
// (see tailKind), so a control-plane restart silently reset the report to
// empty — and that report is the evidence an operator uses to decide a site is
// safe to flip from learning to blocking. The DETECT rows were always durable
// in ClickHouse; nothing read them back. This does.
//
// Tenant-scoped, like every other read here. The in-memory path had no tenant
// predicate at all, so on a multi-site deployment the report mixed sites the
// caller may not own.
//
// `site` is optional ("" = every site in the tenant). from/to are optional
// (0 = no bound): unlike Search this deliberately does NOT default to the last
// 24 hours, because a learning window runs for a business cycle and a silently
// truncated report would understate what a rule would block — the exact error
// that makes a flip-to-blocking decision unsafe.
func (c *Client) LearningStats(ctx context.Context, tenant, site string, from, to int64, sampleCap int) ([]LearningStat, error) {
	var out []LearningStat
	if err := c.queryJSON(ctx, c.learningSQL(tenant, site, from, to, sampleCap), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// learningWhere builds the predicates for the learning report. Split out so a
// test can assert the tenant boundary and the absence of a default time bound
// without needing a live ClickHouse.
func (c *Client) learningWhere(tenant, site string, from, to int64) []string {
	where := []string{
		eq("tenant", tenant),
		// action='DETECT' is exactly what the data plane writes for a
		// would-have-blocked request (see enforce_mode / record_event).
		eq("action", "DETECT"),
		"rule != ''",
		"rule != '-'",
	}
	if site != "" {
		where = append(where, eq("site", site))
	}
	// Bounds only when asked. Deliberately NOT c.timeWhere, which defaults to
	// the last 24 hours — a learning window runs for a business cycle, and a
	// silently truncated report understates what a rule would block, which is
	// the one error that makes a flip-to-blocking decision unsafe.
	if from > 0 {
		where = append(where, fmt.Sprintf("ts >= toDateTime(%d)", from))
	}
	if to > 0 {
		where = append(where, fmt.Sprintf("ts <= toDateTime(%d)", to))
	}
	return where
}

func (c *Client) learningSQL(tenant, site string, from, to int64, sampleCap int) string {
	if sampleCap <= 0 || sampleCap > 20 {
		sampleCap = 5
	}
	// Every rule that contributed, not only each event's leading rule. The
	// report grouped by the event's `rule` column alone, so a false positive
	// that tripped three rules showed one of them (excluding it left the other
	// two still over the threshold), and — code review — a response-leak rule
	// that fired on a request learning mode had already flagged never had a row
	// at all: the event's leading rule is the request's.
	//
	// The leading rule is counted exactly as before, with the event's own
	// severity and attack label; every OTHER rule in the event's `rules` list
	// (JSON, written since 1.1.11) is counted once more with its own severity
	// and message. Rows from before that column have an empty list and count as
	// they always did.
	//
	// argMax over ts for severity/message: the hub's in-memory version let the
	// most recent non-empty value win, and matching that keeps the two sources
	// from disagreeing about the same rule.
	return fmt.Sprintf(
		"SELECT t.1 AS rule_id, "+
			"argMax(t.2, ts) AS severity, "+
			"argMax(t.3, ts) AS message, "+
			"count() AS count, "+
			"formatDateTime(max(ts), '%%Y-%%m-%%dT%%H:%%i:%%SZ', 'UTC') AS last_seen, "+
			"groupUniqArray(%d)(path) AS samples "+
			"FROM (SELECT ts, path, arrayJoin(arrayConcat("+
			"[(toString(rule), toString(severity), attack)], "+
			"arrayFilter(x -> x.1 != '' AND x.1 != rule, "+
			"arrayMap(x -> (JSONExtractString(x, 'id'), JSONExtractString(x, 'sev'), JSONExtractString(x, 'msg')), "+
			"JSONExtractArrayRaw(rules))))) AS t "+
			"FROM %s.waf_events WHERE %s) "+
			"GROUP BY rule_id ORDER BY count DESC LIMIT 500",
		sampleCap, c.db, strings.Join(c.learningWhere(tenant, site, from, to), " AND "))
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
// Export
// ---------------------------------------------------------------------------

// exportColumns is the column list handed to a customer. Deliberately spelled
// out rather than SELECT * so that adding a column to waf_events — which may
// carry internal or sensitive detail — never silently starts appearing in
// customer-facing exports. ts is rendered as an ISO-8601 UTC string, not a unix
// integer: this file is read by a human in a ticket, and a bare epoch is the
// single most common complaint about exported WAF logs.
const exportColumns = `formatDateTime(ts, '%Y-%m-%dT%H:%i:%SZ', 'UTC') AS timestamp_utc, ` +
	`ip, country, site, method, path, query, referer, matched, rule, attack, action, severity, score, status, ` +
	`protocol, request_id, target, mode, threshold, explanation, ja4, ua, rules, headers`

// ExportFormat maps a requested format onto its ClickHouse FORMAT clause, MIME
// type and file extension. Whitelisted — the format string reaches SQL.
type ExportFormat struct {
	Name      string
	chFormat  string
	MediaType string
	Ext       string
}

var exportFormats = map[string]ExportFormat{
	"csv":    {"csv", "CSVWithNames", "text/csv; charset=utf-8", "csv"},
	"ndjson": {"ndjson", "JSONEachRow", "application/x-ndjson; charset=utf-8", "ndjson"},
	"json":   {"json", "JSON", "application/json; charset=utf-8", "json"},
}

// LookupExportFormat resolves a caller-supplied format name.
func LookupExportFormat(name string) (ExportFormat, bool) {
	f, ok := exportFormats[strings.ToLower(strings.TrimSpace(name))]
	return f, ok
}

// ExportCount returns how many events match the filter.
//
// Why the caller counts before streaming: an export is handed to a customer,
// often during an incident. A file that was silently cut off at a row cap is
// worse than no file — it reads as a complete record of the window and quietly
// omits the events that matter. So the caller counts first and refuses an
// oversized export with the real number, rather than truncating. This is also
// the row count written to the audit trail.
func (c *Client) ExportCount(ctx context.Context, f SearchFilter) (int64, error) {
	var rows []struct {
		N int64 `json:"n"`
	}
	sql := fmt.Sprintf("SELECT count() AS n FROM %s.waf_events WHERE %s",
		c.db, strings.Join(c.searchWhere(f), " AND "))
	if err := c.queryJSON(ctx, sql, &rows); err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].N, nil
}

// ExportStream streams matching events in the requested format.
//
// The returned reader is the live ClickHouse response body — the caller copies
// it straight to the HTTP response and MUST Close it. Nothing is buffered in
// control-plane memory, so a year of events for a busy site costs a constant
// number of bytes here rather than proportional heap.
//
// Ordered ts ASC, unlike Search's newest-first: this is a log file, and a log
// file that runs backwards is unreadable to whoever receives it.
func (c *Client) ExportStream(ctx context.Context, f SearchFilter, format ExportFormat) (io.ReadCloser, error) {
	sql := fmt.Sprintf(
		"SELECT %s FROM %s.waf_events WHERE %s ORDER BY ts ASC",
		exportColumns, c.db, strings.Join(c.searchWhere(f), " AND "))
	if f.Limit > 0 {
		sql += fmt.Sprintf(" LIMIT %d", f.Limit)
	}
	return c.queryStream(ctx,
		sql+" SETTINGS output_format_json_quote_64bit_integers = 0 FORMAT "+format.chFormat)
}

// queryStream POSTs raw SQL and returns the undrained response body. Unlike
// query() it does not read the body into memory; the caller owns closing it.
func (c *Client) queryStream(ctx context.Context, sql string) (io.ReadCloser, error) {
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
	// The shared client's 10s timeout covers the whole body for a streamed
	// response, which would cut long exports off mid-file. Use a transport-level
	// clone with no overall deadline; cancellation rides on ctx instead.
	hc := &http.Client{Transport: c.http.Transport}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		resp.Body.Close()
		return nil, fmt.Errorf("clickhouse HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return resp.Body, nil
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

// facetSQL builds the Facets query. Split out so the SQL can be tested without
// a ClickHouse server.
func (c *Client) facetSQL(column, tenant string, from, to int64, limit int) (string, error) {
	col, ok := facetColumn(column)
	if !ok {
		return "", fmt.Errorf("invalid facet column %q", column)
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	// A rule facet also carries the rule's most recent attack message, the same
	// argMax the learning report uses, so the two never name a rule differently.
	label := ""
	if col == "rule" {
		label = ", argMax(attack, ts) AS label"
	}
	// Tenant-scoped (isolation boundary), like Search.
	where := append(c.timeWhere(from, to), eq("tenant", tenant))
	return fmt.Sprintf(
		"SELECT %s AS key, count() AS count%s FROM %s.waf_events WHERE %s AND %s != '' "+
			"GROUP BY key ORDER BY count DESC LIMIT %d",
		col, label, c.db, strings.Join(where, " AND "), col, limit), nil
}

// facetColumn whitelists groupable columns (prevents SQL injection via column).
// `attack` is the attack-type breakdown — the first view SafeLine and F5 open
// on — and was the one event column an operator could not group by.
func facetColumn(c string) (string, bool) {
	switch strings.ToLower(c) {
	case "rule", "ip", "country", "action", "site", "severity", "protocol", "attack":
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
