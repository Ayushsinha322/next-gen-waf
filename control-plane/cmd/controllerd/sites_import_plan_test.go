package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

func storedShop() db.SiteRow {
	return db.SiteRow{
		ID:       "00000000-0000-4000-8000-000000000001",
		Name:     "shop",
		Domains:  []string{"shop.example.in"},
		Upstream: json.RawMessage(`{"servers":[{"host":"10.0.0.5","port":8080}],"lb":"round_robin","timeout_secs":45}`),
		WafPolicy: json.RawMessage(`{"mode":"learning","paranoia_level":2,"anomaly_threshold":10,` +
			`"rule_exclusions":[{"rule_id":"942100","targets":["ARGS:q"]}],` +
			`"path_overrides":[{"path_prefix":"/api","mode":"learning"}],` +
			`"rate_limit":{"enabled":true,"per_ip":{"rps":200,"burst":100}}}`),
	}
}

func decode(t *testing.T, raw json.RawMessage) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return m
}

// The import box's own example applied to an existing site used to REPLACE its
// policy and upstream: exclusions, path overrides, rate limits and the origin
// timeout were wiped. Keys the document leaves out must keep their stored values.
func TestImportMergesOntoAnExistingSiteInsteadOfReplacingIt(t *testing.T) {
	doc := []yamlSite{{Name: "shop", WafPolicy: map[string]interface{}{"mode": "blocking"}}}
	plan, problems := planImport(doc, []db.SiteRow{storedShop()})
	if len(problems) > 0 {
		t.Fatalf("a valid partial document was refused: %+v", problems)
	}
	if len(plan) != 1 || plan[0].cur == nil {
		t.Fatalf("expected one update of the stored site, got %+v", plan)
	}
	waf := decode(t, plan[0].wafJSON)
	if waf["mode"] != "blocking" {
		t.Errorf("the document's mode was not applied: %v", waf["mode"])
	}
	for _, kept := range []string{"rule_exclusions", "path_overrides", "rate_limit", "anomaly_threshold"} {
		if _, ok := waf[kept]; !ok {
			t.Errorf("%s was wiped by an import that did not mention it", kept)
		}
	}
	up := decode(t, plan[0].upJSON)
	if up["timeout_secs"] != float64(45) || up["servers"] == nil {
		t.Errorf("the stored upstream was not kept: %v", up)
	}
	if strings.Join(plan[0].domains, ",") != "shop.example.in" {
		t.Errorf("stored domains were not kept: %v", plan[0].domains)
	}
}

func TestImportRefusesDomainsAnotherSiteAlreadyClaims(t *testing.T) {
	doc := []yamlSite{{
		Name:     "shop-copy",
		Domains:  []string{"SHOP.example.in"},
		Upstream: map[string]interface{}{"servers": []interface{}{"10.0.0.6:8080"}},
	}}
	if _, problems := planImport(doc, []db.SiteRow{storedShop()}); len(problems) == 0 {
		t.Fatal("an import claimed a domain an existing site protects — the data plane would serve one of them at random")
	}
}

func TestImportRefusesTwoDocumentSitesClaimingOneDomain(t *testing.T) {
	up := map[string]interface{}{"servers": []interface{}{"10.0.0.6:8080"}}
	doc := []yamlSite{
		{Name: "a", Domains: []string{"portal.example.in"}, Upstream: up},
		{Name: "b", Domains: []string{"portal.example.in"}, Upstream: up},
	}
	_, problems := planImport(doc, nil)
	found := false
	for _, p := range problems {
		found = found || strings.Contains(p.Problem, "also claimed")
	}
	if !found {
		t.Fatalf("two document sites claiming one domain were accepted: %+v", problems)
	}
}

// A string paranoia level was stored, then silently skipped by every sync while
// the site still listed as active.
func TestImportRefusesAMistypedPolicyValue(t *testing.T) {
	doc := []yamlSite{{
		Name:      "shop",
		WafPolicy: map[string]interface{}{"paranoia_level": "2"},
	}}
	if _, problems := planImport(doc, []db.SiteRow{storedShop()}); len(problems) == 0 {
		t.Fatal(`paranoia_level "2" (a string) was accepted`)
	}
}
