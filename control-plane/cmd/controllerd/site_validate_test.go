package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

func fields(problems []SiteConfigProblem) string {
	var b strings.Builder
	for _, p := range problems {
		b.WriteString(p.String())
		b.WriteString("; ")
	}
	return b.String()
}

func hasField(problems []SiteConfigProblem, field string) bool {
	for _, p := range problems {
		if p.Field == field {
			return true
		}
	}
	return false
}

func TestValidateSiteConfigAcceptsGoodConfig(t *testing.T) {
	problems := validateSiteConfig(
		"shop.example.com",
		[]string{"shop.example.com", "www.shop.example.com"},
		json.RawMessage(`{"servers":["10.0.0.5:8080"],"lb":"round_robin"}`),
		json.RawMessage(`{"mode":"blocking","paranoia_level":2,"anomaly_threshold":5}`),
	)
	if len(problems) != 0 {
		t.Fatalf("valid config rejected: %s", fields(problems))
	}
}

func TestValidateSiteConfigAcceptsObjectServerForm(t *testing.T) {
	problems := validateSiteConfig("api.example.com", []string{"api.example.com"},
		json.RawMessage(`{"servers":[{"host":"10.0.0.5","port":8443,"tls":true}]}`),
		json.RawMessage(`{"mode":"learning"}`))
	if len(problems) != 0 {
		t.Fatalf("valid object-form upstream rejected: %s", fields(problems))
	}
}

// TestValidateSiteConfigCatchesTheSilentDropCause is the point of the whole fix.
// Malformed upstream JSON is exactly what made buildRustUpstream fail inside
// handleInternalConfig, where the error was swallowed by `continue` and the site
// silently disappeared from the data plane's configuration.
func TestValidateSiteConfigCatchesTheSilentDropCause(t *testing.T) {
	problems := validateSiteConfig("shop.example.com", []string{"shop.example.com"},
		json.RawMessage(`{"servers": "not-an-array-or-object"}`),
		json.RawMessage(`{"mode":"blocking"}`))
	if len(problems) == 0 {
		t.Fatal("malformed upstream accepted — it would vanish at sync time instead")
	}
	if !hasField(problems, "upstream") && !hasField(problems, "upstream.servers") {
		t.Errorf("expected an upstream problem, got: %s", fields(problems))
	}
}

func TestValidateSiteConfigRejectsInvalidJSON(t *testing.T) {
	for _, tc := range []struct {
		name, field       string
		upstream, wafJSON string
	}{
		{"upstream", "upstream", `{"servers":[`, `{}`},
		{"waf_policy", "waf_policy", `{"servers":["10.0.0.1:80"]}`, `{"mode":`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			problems := validateSiteConfig("s.example.com", []string{"s.example.com"},
				json.RawMessage(tc.upstream), json.RawMessage(tc.wafJSON))
			if !hasField(problems, tc.field) {
				t.Errorf("invalid %s JSON accepted; problems: %s", tc.name, fields(problems))
			}
		})
	}
}

// A site with no upstream servers converts cleanly but is a black hole: traffic
// arrives and has nowhere to go. That is a silent outage, so it must be rejected.
func TestValidateSiteConfigRejectsEmptyUpstream(t *testing.T) {
	for _, up := range []string{`{}`, `{"servers":[]}`, `{"servers":[],"lb":"round_robin"}`} {
		problems := validateSiteConfig("s.example.com", []string{"s.example.com"},
			json.RawMessage(up), json.RawMessage(`{}`))
		if !hasField(problems, "upstream.servers") {
			t.Errorf("upstream %s accepted with no servers; problems: %s", up, fields(problems))
		}
	}
}

func TestValidateSiteConfigRequiresNameAndDomains(t *testing.T) {
	problems := validateSiteConfig("  ", nil,
		json.RawMessage(`{"servers":["10.0.0.1:80"]}`), json.RawMessage(`{}`))
	if !hasField(problems, "name") {
		t.Errorf("empty name accepted: %s", fields(problems))
	}
	if !hasField(problems, "domains") {
		t.Errorf("missing domains accepted: %s", fields(problems))
	}
}

func TestValidateSiteConfigRejectsMalformedDomains(t *testing.T) {
	problems := validateSiteConfig("s.example.com",
		[]string{"https://s.example.com", "good.example.com", "has space", ""},
		json.RawMessage(`{"servers":["10.0.0.1:80"]}`), json.RawMessage(`{}`))
	for _, want := range []string{"domains[0]", "domains[2]", "domains[3]"} {
		if !hasField(problems, want) {
			t.Errorf("expected a problem for %s; got: %s", want, fields(problems))
		}
	}
	if hasField(problems, "domains[1]") {
		t.Errorf("the valid domain was flagged: %s", fields(problems))
	}
}

func TestValidateSiteConfigRejectsHostPortInHostField(t *testing.T) {
	// A common operator slip: the whole host:port pasted into `host`, which
	// resolves to nothing.
	problems := validateSiteConfig("s.example.com", []string{"s.example.com"},
		json.RawMessage(`{"servers":[{"host":"10.0.0.5:8080","port":8080}]}`),
		json.RawMessage(`{}`))
	if !hasField(problems, "upstream.servers[0].host") {
		t.Errorf("host:port in the host field accepted: %s", fields(problems))
	}
}

func TestValidateSiteConfigRejectsOutOfRangePorts(t *testing.T) {
	for _, port := range []string{"70000", "-1", "65536"} {
		problems := validateSiteConfig("s.example.com", []string{"s.example.com"},
			json.RawMessage(`{"servers":[{"host":"10.0.0.5","port":`+port+`}]}`),
			json.RawMessage(`{}`))
		if !hasField(problems, "upstream.servers[0].port") {
			t.Errorf("port %s accepted: %s", port, fields(problems))
		}
	}
}

// Port 0 means "unspecified"; buildRustUpstream deliberately defaults it to 80,
// so the validator must accept it rather than reject a config the data plane will
// happily run. Validating the converter's OUTPUT rather than the raw input is what
// keeps the two in agreement.
func TestValidateSiteConfigAcceptsOmittedPortAsHTTPDefault(t *testing.T) {
	for _, up := range []string{
		`{"servers":[{"host":"10.0.0.5","port":0}]}`,
		`{"servers":[{"host":"10.0.0.5"}]}`,
		`{"servers":["10.0.0.5"]}`,
	} {
		problems := validateSiteConfig("s.example.com", []string{"s.example.com"},
			json.RawMessage(up), json.RawMessage(`{}`))
		if len(problems) != 0 {
			t.Errorf("upstream %s rejected, but the converter defaults the port to 80: %s", up, fields(problems))
		}
	}
}

// These policy values convert cleanly but silently weaken or disable protection,
// which is worse than an outright error because nothing looks wrong.
func TestValidateWafPolicyValues(t *testing.T) {
	tests := []struct {
		name, policy, wantField string
	}{
		{"unknown mode", `{"mode":"monitor"}`, "waf_policy.mode"},
		{"paranoia too high", `{"paranoia_level":9}`, "waf_policy.paranoia_level"},
		{"paranoia too low", `{"paranoia_level":0}`, "waf_policy.paranoia_level"},
		{"threshold zero blocks everything", `{"anomaly_threshold":0}`, "waf_policy.anomaly_threshold"},
		{"negative threshold", `{"anomaly_threshold":-5}`, "waf_policy.anomaly_threshold"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			problems := validateSiteConfig("s.example.com", []string{"s.example.com"},
				json.RawMessage(`{"servers":["10.0.0.1:80"]}`), json.RawMessage(tc.policy))
			if !hasField(problems, tc.wantField) {
				t.Errorf("accepted %s; problems: %s", tc.policy, fields(problems))
			}
		})
	}
}

func TestValidateWafPolicyAcceptsValidModes(t *testing.T) {
	for _, mode := range []string{"blocking", "learning", "off"} {
		problems := validateSiteConfig("s.example.com", []string{"s.example.com"},
			json.RawMessage(`{"servers":["10.0.0.1:80"]}`),
			json.RawMessage(`{"mode":"`+mode+`","paranoia_level":1,"anomaly_threshold":1}`))
		if len(problems) != 0 {
			t.Errorf("mode %q rejected: %s", mode, fields(problems))
		}
	}
}

// A patch can be individually fine yet produce an unusable site once combined with
// what is already stored, so the merged result is what must be validated.
func TestMergedSiteForValidationAppliesPartialUpdate(t *testing.T) {
	cur := db.SiteRow{
		Name:      "old.example.com",
		Domains:   []string{"old.example.com"},
		Upstream:  json.RawMessage(`{"servers":["10.0.0.1:80"]}`),
		WafPolicy: json.RawMessage(`{"mode":"blocking"}`),
	}

	// Empty patch preserves everything.
	name, domains, up, waf := mergedSiteForValidation(cur, db.UpdateSiteRequest{})
	if name != cur.Name || len(domains) != 1 || string(up) != string(cur.Upstream) || string(waf) != string(cur.WafPolicy) {
		t.Fatalf("empty patch altered the merge: %q %v %s %s", name, domains, up, waf)
	}

	// A patch that only replaces the upstream keeps the stored name/domains, and
	// the bad upstream is caught against the merged whole.
	newName := "new.example.com"
	name, domains, up, waf = mergedSiteForValidation(cur, db.UpdateSiteRequest{
		Name:     &newName,
		Upstream: json.RawMessage(`{"servers":[]}`),
	})
	if name != newName {
		t.Errorf("name patch not applied: %q", name)
	}
	if len(domains) != 1 || domains[0] != "old.example.com" {
		t.Errorf("domains should have been preserved, got %v", domains)
	}
	if string(waf) != string(cur.WafPolicy) {
		t.Errorf("waf_policy should have been preserved, got %s", waf)
	}
	if problems := validateSiteConfig(name, domains, up, waf); !hasField(problems, "upstream.servers") {
		t.Errorf("merged config with an emptied upstream was accepted: %s", fields(problems))
	}
}

func TestValidateSiteRowUsesStoredFields(t *testing.T) {
	// The read-time backstop must flag exactly the rows that would be dropped.
	bad := db.SiteRow{
		Name:     "legacy.example.com",
		Domains:  []string{"legacy.example.com"},
		Upstream: json.RawMessage(`{"servers": 12345}`),
	}
	if problems := validateSiteRow(bad); len(problems) == 0 {
		t.Error("a row that cannot convert was reported as valid")
	}
	good := db.SiteRow{
		Name:      "ok.example.com",
		Domains:   []string{"ok.example.com"},
		Upstream:  json.RawMessage(`{"servers":["10.0.0.1:80"]}`),
		WafPolicy: json.RawMessage(`{"mode":"blocking"}`),
	}
	if problems := validateSiteRow(good); len(problems) != 0 {
		t.Errorf("a good row was flagged: %s", fields(problems))
	}
}

// Nothing ever checked whether a hostname was already claimed. The data plane
// routes purely by Host header, so two sites listing "portal.example.com" both
// matched and whichever the node loaded last won — silently, with no error at
// create time and no way to see from the console which policy was in force. On
// a shared internal node hosting several applications, an operator could point a
// new site at a hostname an existing site already protected and quietly replace
// its policy.
func TestDomainConflictsAcrossSites(t *testing.T) {
	existing := []db.SiteRow{
		{ID: "site-a", Name: "portal", Domains: []string{"portal.example.com", "www.portal.example.com"}},
		{ID: "site-b", Name: "api", Domains: []string{"api.example.com"}},
	}

	// A fresh site claiming a taken hostname must be reported, and the message
	// must name the site that already owns it — "conflict" alone leaves the
	// operator hunting.
	got := domainConflicts(existing, []string{"new.example.com", "api.example.com"}, "")
	if len(got) != 1 {
		t.Fatalf("expected exactly one conflict, got %d: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Problem, `"api"`) {
		t.Errorf("conflict must name the owning site, got %q", got[0].Problem)
	}
	if got[0].Field != "domains[1]" {
		t.Errorf("conflict must point at the offending index, got %q", got[0].Field)
	}

	// Host matching is case-insensitive, so a different case is the same claim.
	if got := domainConflicts(existing, []string{"API.Example.COM"}, ""); len(got) != 1 {
		t.Errorf("case-differing domain must still conflict, got %+v", got)
	}

	// An UPDATE must be able to keep its own domains without conflicting with
	// itself, or no site could ever be edited.
	if got := domainConflicts(existing, []string{"portal.example.com"}, "site-a"); len(got) != 0 {
		t.Errorf("a site must not conflict with itself: %+v", got)
	}
	// ...but it must still conflict with OTHER sites.
	if got := domainConflicts(existing, []string{"api.example.com"}, "site-a"); len(got) != 1 {
		t.Errorf("an update must still conflict with another site: %+v", got)
	}

	// No false positives on genuinely new hostnames.
	if got := domainConflicts(existing, []string{"fresh.example.com"}, ""); len(got) != 0 {
		t.Errorf("unclaimed domain must not conflict: %+v", got)
	}
}

// A site listing the same hostname twice is a mistake worth catching at the
// source, before it reaches the store.
func TestDuplicateDomainsWithinOneRequest(t *testing.T) {
	problems := validateSiteConfig("app", []string{"a.example.com", "A.example.com"},
		json.RawMessage(`{"servers":[{"host":"10.0.0.1","port":8080}]}`),
		json.RawMessage(`{"mode":"learning","anomaly_threshold":10,"paranoia_level":2}`))
	found := false
	for _, p := range problems {
		if strings.Contains(p.Problem, "already listed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a repeated domain must be reported: %+v", problems)
	}
}

// The wizard's dry-run must run the same domain-ownership check as create and
// update; it once said a duplicate domain was fine and the save then 409'd.
func TestValidateDryRunChecksDomainOwnership(t *testing.T) {
	src, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	i := strings.Index(s, "func handleValidateSite(")
	if i < 0 {
		t.Fatal("handleValidateSite not found")
	}
	body := s[i:]
	if j := strings.Index(body[1:], "\nfunc "); j > 0 {
		body = body[:j+1]
	}
	if !strings.Contains(body, "domainConflicts(existing, domains, req.SiteID)") {
		t.Fatal("handleValidateSite no longer checks whether another site owns the domains")
	}
}

func feedPolicy(t *testing.T, url string) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ip_reputation": map[string]any{
		"feeds": []map[string]string{{"url": url, "interval": "1h", "format": "cidr"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Every data-plane node fetches each feed URL itself, and a file:// URL used to
// be read off the node's own disk. Only http(s) with a host is accepted.
func TestFeedURLsAreRefusedUnlessHTTP(t *testing.T) {
	const field = "waf_policy.ip_reputation.feeds[0].url"
	cases := []struct{ url, want string }{
		{"file:///etc/passwd", "http:// or https://"},
		{"FILE:///etc/passwd", "http:// or https://"},
		{"ftp://feeds.example/list", "http:// or https://"},
		{"gopher://feeds.example/", "http:// or https://"},
		{"javascript:alert(1)", "http:// or https://"},
		{"//feeds.example/list", "http:// or https://"},
		{"feeds.example/list.txt", "http:// or https://"},
		{"http:///list", "has no host"},
		{"http://feeds.example:99999/list", "ports are 1-65535"},
		{"http://feeds.example/my list.txt", "contains a space"},
		{"   ", "must not be empty"},
		{"https://feeds.example/" + strings.Repeat("a", maxFeedURLLength), "longest accepted is 2048"},
	}
	for _, c := range cases {
		ps := validateWafPolicyValues(feedPolicy(t, c.url))
		if len(ps) != 1 || ps[0].Field != field || !strings.Contains(ps[0].Problem, c.want) {
			t.Errorf("%.60q: got %s, want one problem on %s mentioning %q", c.url, fields(ps), field, c.want)
		}
	}
}

// A feed the data plane cannot deserialize makes it reject the whole site, so
// the list's shape is refused too — without hiding the policy's other checks.
func TestMalformedFeedListIsRefused(t *testing.T) {
	cases := []struct{ policy, field, want string }{
		{`{"ip_reputation":{"feeds":"https://feeds.example/list"}}`, "waf_policy.ip_reputation.feeds", "must be a list"},
		{`{"ip_reputation":{"feeds":[{"interval":"1h"}]}}`, "waf_policy.ip_reputation.feeds[0].url", "is required"},
		{`{"ip_reputation":{"feeds":[null]}}`, "waf_policy.ip_reputation.feeds[0].url", "is required"},
		{`{"ip_reputation":{"feeds":[{"url":42}]}}`, "waf_policy.ip_reputation.feeds[0].url", "must be a string"},
	}
	for _, c := range cases {
		ps := problemsFor(t, c.policy)
		if len(ps) != 1 || ps[0].Field != c.field || !strings.Contains(ps[0].Problem, c.want) {
			t.Errorf("%s: got %s, want one problem on %s mentioning %q", c.policy, fields(ps), c.field, c.want)
		}
	}
	ps := problemsFor(t, `{"ip_reputation":{"block":["not-an-ip"],"feeds":"x"}}`)
	if !hasField(ps, "waf_policy.ip_reputation.block") || !hasField(ps, "waf_policy.ip_reputation.feeds") {
		t.Errorf("a malformed feed list hid the block-list check: %s", fields(ps))
	}
}

func TestGoodFeedURLsPass(t *testing.T) {
	for _, pol := range []string{
		`{"ip_reputation":{"feeds":[
			{"url":"https://iplists.firehol.org/files/firehol_level1.netset","interval":"1h","format":"cidr"},
			{"url":"HTTP://10.0.0.5:8080/list.txt"},
			{"url":"https://user:pass@feeds.example/list?key=abc"},
			{"url":"http://[2001:db8::1]/list"},
			{"url":" https://feeds.example/list "}]}}`,
		`{"ip_reputation":{"feeds":[]}}`,
		`{"ip_reputation":{"feeds":null}}`,
		`{"ip_reputation":{"allow":["10.0.0.0/8"]}}`,
	} {
		if ps := problemsFor(t, pol); len(ps) != 0 {
			t.Errorf("%s: unexpected problems %s", pol, fields(ps))
		}
	}
}

// Create validates the request and update validates the merge with the stored
// row; a problem from either is the handler's 400.
func TestFeedURLIsCheckedOnCreateAndUpdate(t *testing.T) {
	const field = "waf_policy.ip_reputation.feeds[0].url"
	up := json.RawMessage(`{"servers":["10.0.0.5:8080"]}`)
	bad := json.RawMessage(`{"mode":"blocking","ip_reputation":{"feeds":[{"url":"file:///etc/shadow"}]}}`)

	if ps := validateSiteConfig("shop", []string{"shop.example.com"}, up, bad); !hasField(ps, field) {
		t.Errorf("create accepted a file:// feed: %s", fields(ps))
	}

	cur := db.SiteRow{
		Name:      "shop",
		Domains:   []string{"shop.example.com"},
		Upstream:  up,
		WafPolicy: json.RawMessage(`{"mode":"blocking"}`),
	}
	name, domains, u, waf := mergedSiteForValidation(cur, db.UpdateSiteRequest{WafPolicy: bad})
	if ps := validateSiteConfig(name, domains, u, waf); !hasField(ps, field) {
		t.Errorf("update accepted a file:// feed: %s", fields(ps))
	}
}
