package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

// jsonNulls lists the paths of every JSON null in v.
func jsonNulls(v any, path string, out *[]string) {
	switch t := v.(type) {
	case nil:
		*out = append(*out, path)
	case map[string]any:
		for k, x := range t {
			jsonNulls(x, path+"."+k, out)
		}
	case []any:
		for i, x := range t {
			jsonNulls(x, fmt.Sprintf("%s[%d]", path, i), out)
		}
	}
}

// The config the data plane receives must contain no JSON null at all.
//
// Not a style rule: the Rust side's non-Option fields (`rules: Vec<String>` and
// friends) reject null even where they default an absent field, and before the
// data plane parsed sites one at a time, one null anywhere made every node
// reject the entire sync. A site switched to mode "off" did exactly that —
// `var rules []string` stayed nil and marshalled as `"rules": null` — freezing
// config delivery for the whole fleet (proven live on the 3-node cluster,
// 2026-09-23). Every policy shape below is one an operator can reach.
func TestSiteConfigForTheDataPlaneHasNoNulls(t *testing.T) {
	policies := map[string]string{
		"off":               `{"mode":"off"}`,
		"off with policy":   `{"mode":"off","paranoia_level":2,"rule_categories":["sqli"],"geoip":{"block_countries":["US"]}}`,
		"learning default":  `{"mode":"learning"}`,
		"blocking default":  `{"mode":"blocking"}`,
		"no categories":     `{"mode":"blocking","rule_categories":[]}`,
		"empty policy":      `{}`,
		"everything empty":  `{"mode":"blocking","path_overrides":[],"rule_exclusions":[],"allowed_methods":[],"geoip":{},"ip_reputation":{},"rate_limit":{}}`,
		"typical wizard":    `{"mode":"learning","paranoia_level":1,"anomaly_threshold":10,"rule_categories":["sqli","xss"],"security_headers":{"custom":[]},"ml":{"enable":true}}`,
		"geo + ip lists":    `{"mode":"blocking","geoip":{"allow_countries":["IN"]},"ip_reputation":{"block":["203.0.113.7/32"],"allow":[]}}`,
		"path override off": `{"mode":"blocking","path_overrides":[{"path_prefix":"/static/","mode":"off"}]}`,
	}
	for name, pol := range policies {
		t.Run(name, func(t *testing.T) {
			row := db.SiteRow{
				ID: "s1", Name: "s1", Domains: []string{"a.example"}, Status: "active",
				Upstream:  json.RawMessage(`{"servers":[{"host":"10.0.0.5","port":80}]}`),
				WafPolicy: json.RawMessage(pol),
			}
			cfg, err := siteRowToRustConfig(row)
			if err != nil {
				t.Fatalf("siteRowToRustConfig: %v", err)
			}
			b, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var v any
			if err := json.Unmarshal(b, &v); err != nil {
				t.Fatal(err)
			}
			var nulls []string
			jsonNulls(v, "site", &nulls)
			if len(nulls) > 0 {
				t.Fatalf("config for the data plane contains null at %s — a null in a non-Option "+
					"Rust field makes the node reject it:\n%s", strings.Join(nulls, ", "), b)
			}
		})
	}
}

// Mode off still sends a rules LIST (empty), not null and not the CRS files.
func TestModeOffSendsAnEmptyRulesList(t *testing.T) {
	waf, err := buildRustWaf(json.RawMessage(`{"mode":"off"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(waf["rules"])
	if string(b) != "[]" {
		t.Fatalf(`mode off: rules = %s, want []`, b)
	}
}
