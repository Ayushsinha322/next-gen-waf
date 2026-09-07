package clickhouse

import (
	"context"
	"fmt"
	"strings"
)

// ReportSummary is everything a scheduled report needs from the event store for
// one tenant, one optional site and one period, gathered with GROUP BY queries
// rather than by paging events through Go. Every query carries the tenant
// predicate (the security boundary) and, when set, the site predicate.
type ReportSummary struct {
	Total      int64       `json:"total"`
	Blocked    int64       `json:"blocked"`
	Detected   int64       `json:"detected"` // learning-mode would-have-blocked
	Sources    int64       `json:"sources"`  // distinct IPs
	ByAction   []Facet     `json:"by_action"`
	BySeverity []Facet     `json:"by_severity"`
	ByAttack   []Facet     `json:"by_attack"`
	ByCountry  []Facet     `json:"by_country"`
	TopRules   []RuleHit   `json:"top_rules"`
	TopSources []Attacker  `json:"top_sources"`
	ByDay      []DayBucket `json:"by_day"`
}

type DayBucket struct {
	Day     string `json:"day"`
	Total   int64  `json:"total"`
	Blocked int64  `json:"blocked"`
}

// reportWhere is the shared predicate: time window, tenant, optional site.
func (c *Client) reportWhere(tenant, site string, from, to int64) string {
	where := append(c.timeWhere(from, to), eq("tenant", tenant))
	if site != "" {
		where = append(where, eq("site", site))
	}
	return strings.Join(where, " AND ")
}

// ReportSummary runs the aggregate queries behind a scheduled report.
func (c *Client) ReportSummary(ctx context.Context, tenant, site string, from, to int64) (*ReportSummary, error) {
	if !c.enabled {
		return nil, fmt.Errorf("clickhouse not configured")
	}
	w := c.reportWhere(tenant, site, from, to)
	tbl := c.db + ".waf_events"
	out := &ReportSummary{}

	var totals []struct {
		Total    int64 `json:"total"`
		Blocked  int64 `json:"blocked"`
		Detected int64 `json:"detected"`
		Sources  int64 `json:"sources"`
	}
	if err := c.queryJSON(ctx, fmt.Sprintf(
		"SELECT count() AS total, countIf(action = 'BLOCK') AS blocked, countIf(action = 'DETECT') AS detected, "+
			"uniqExact(ip) AS sources FROM %s WHERE %s", tbl, w), &totals); err != nil {
		return nil, err
	}
	if len(totals) == 1 {
		out.Total, out.Blocked, out.Detected, out.Sources = totals[0].Total, totals[0].Blocked, totals[0].Detected, totals[0].Sources
	}
	facet := func(col string, limit int) ([]Facet, error) {
		var f []Facet
		err := c.queryJSON(ctx, fmt.Sprintf(
			"SELECT %s AS key, count() AS count FROM %s WHERE %s AND %s != '' GROUP BY %s ORDER BY count DESC LIMIT %d",
			col, tbl, w, col, col, limit), &f)
		return f, err
	}
	var err error
	if out.ByAction, err = facet("action", 10); err != nil {
		return nil, err
	}
	if out.BySeverity, err = facet("severity", 10); err != nil {
		return nil, err
	}
	if out.ByAttack, err = facet("attack", 12); err != nil {
		return nil, err
	}
	if out.ByCountry, err = facet("country", 10); err != nil {
		return nil, err
	}
	if err = c.queryJSON(ctx, fmt.Sprintf(
		"SELECT rule AS rule_id, count() AS count, countIf(action = 'BLOCK') AS blocked FROM %s WHERE %s AND rule != '' "+
			"GROUP BY rule ORDER BY count DESC LIMIT 15", tbl, w), &out.TopRules); err != nil {
		return nil, err
	}
	if err = c.queryJSON(ctx, fmt.Sprintf(
		"SELECT ip, anyLast(country) AS country, count() AS requests, countIf(action = 'BLOCK') AS blocked, "+
			"toUnixTimestamp(max(ts)) AS last_seen FROM %s WHERE %s AND ip != '' GROUP BY ip ORDER BY requests DESC LIMIT 15",
		tbl, w), &out.TopSources); err != nil {
		return nil, err
	}
	if err = c.queryJSON(ctx, fmt.Sprintf(
		"SELECT toString(toDate(ts)) AS day, count() AS total, countIf(action = 'BLOCK') AS blocked FROM %s WHERE %s "+
			"GROUP BY day ORDER BY day", tbl, w), &out.ByDay); err != nil {
		return nil, err
	}
	return out, nil
}
