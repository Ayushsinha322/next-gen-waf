package main

import (
	"encoding/json"
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
