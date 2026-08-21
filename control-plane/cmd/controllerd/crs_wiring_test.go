package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// crsRulesDir is the shipped CRS directory, relative to this package.
func crsRulesDir() string {
	return filepath.Join("..", "..", "..", "rules", "owasp-crs", "rules")
}

// The bug this file exists to prevent, in one sentence: the image shipped 25 CRS
// rule files and the control plane could name only 13, so 222 rules — including
// every RESPONSE-* family, i.e. the whole response-body inspection capability —
// were compiled into the data plane and unreachable by any site configuration.
//
// Nothing detected it. The rules imported, the engine supported the phase, the
// installer's verify.sh passed, and the dashboard showed "13/13 enabled" — which
// was true and still meant a third of the rule set could not run.
//
// TestEveryShippedCRSFileIsAccountedFor is the guard: every .conf on disk must be
// either wired to a category or listed as a deliberate exclusion. A CRS upgrade
// that adds a file now fails this test instead of quietly shipping dead rules.
func TestEveryShippedCRSFileIsAccountedFor(t *testing.T) {
	dir := crsRulesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("CRS rules not present at %s: %v", dir, err)
	}

	wired := map[string]string{} // file -> category key
	for k, f := range crsCategoryFiles {
		wired[filepath.Base(f)] = k
	}
	unwired := map[string]bool{}
	for _, f := range crsUnwiredFiles {
		unwired[filepath.Base(f)] = true
	}

	var orphans []string
	shipped := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".conf") {
			continue
		}
		shipped++
		if _, ok := wired[name]; ok {
			continue
		}
		if unwired[name] {
			continue
		}
		orphans = append(orphans, name)
	}

	if len(orphans) > 0 {
		sort.Strings(orphans)
		t.Errorf("%d shipped CRS file(s) are neither wired to a category nor listed "+
			"in crsUnwiredFiles, so they ship into the image and no site "+
			"configuration can ever load them:\n  %s\n\n"+
			"Either add a category key in crsCategoryFiles (and the dashboard's "+
			"CRS_CATEGORIES), or record the decision in crsUnwiredFiles with the "+
			"reason.", len(orphans), strings.Join(orphans, "\n  "))
	}
	if shipped == 0 {
		t.Fatal("found no .conf files — the test is not measuring anything")
	}
	t.Logf("%d shipped CRS files: %d wired, %d deliberately unwired",
		shipped, len(wired), len(unwired))
}

// Every wired category must point at a file that actually exists. A typo here is
// invisible at runtime: the data plane logs a load failure per site and keeps
// serving with fewer rules than the operator selected.
func TestWiredCategoryFilesExist(t *testing.T) {
	dir := crsRulesDir()
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("CRS rules not present: %v", err)
	}
	for k, rel := range crsCategoryFiles {
		// rel is "rules/owasp-crs/rules/X.conf" as the data plane sees it.
		p := filepath.Join("..", "..", "..", rel)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("category %q -> %s does not exist", k, rel)
		}
	}
	for _, rel := range crsUnwiredFiles {
		p := filepath.Join("..", "..", "..", rel)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("crsUnwiredFiles names %s, which does not exist — stale entry", rel)
		}
	}
}

// A key present in crsCategoryFiles but absent from crsCategoryOrder is silently
// undeliverable: crsFilesForCategories walks the ORDER, so an unordered key is
// accepted by the API, echoed back to the dashboard, and dropped on the way to
// the data plane. That is the exact shape of this project's recurring
// silently-inert defect, so it is asserted in both directions.
func TestCategoryMapAndOrderAgree(t *testing.T) {
	inOrder := map[string]bool{}
	for _, k := range crsCategoryOrder {
		if inOrder[k] {
			t.Errorf("category %q appears twice in crsCategoryOrder", k)
		}
		inOrder[k] = true
		if _, ok := crsCategoryFiles[k]; !ok {
			t.Errorf("crsCategoryOrder names %q, which has no file in crsCategoryFiles", k)
		}
	}
	for k := range crsCategoryFiles {
		if !inOrder[k] {
			t.Errorf("category %q has a file but is not in crsCategoryOrder — "+
				"it would be accepted by the API and never reach the data plane", k)
		}
	}
}

// Response families are opt-in. A stored policy that names no categories at all
// predates these keys, and must keep behaving exactly as it did: no response
// buffering, no single-match response blocking.
func TestEmptySelectionExcludesResponseFamilies(t *testing.T) {
	files := crsFilesForCategories(nil)
	if len(files) == 0 {
		t.Fatal("empty selection returned no files")
	}
	for _, f := range files {
		if strings.Contains(filepath.Base(f), "RESPONSE-") {
			t.Errorf("empty selection returned %s — response inspection must never "+
				"be enabled implicitly", f)
		}
	}
	// And it must still return the full request set.
	if want := len(crsCategoryOrder) - len(crsResponseCategories); len(files) != want {
		t.Errorf("empty selection returned %d files, want %d request families",
			len(files), want)
	}
}

// The other half: when an operator DOES ask for a response family, it has to
// arrive. Selecting it and getting nothing back is how "enabled" becomes a lie.
func TestSelectedResponseFamilyIsDelivered(t *testing.T) {
	files := crsFilesForCategories([]string{"sqli", "leak_sql", "web_shells"})
	joined := strings.Join(files, " ")
	for _, want := range []string{
		"REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
		"RESPONSE-951-DATA-LEAKAGES-SQL.conf",
		"RESPONSE-955-WEB-SHELLS.conf",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("selection did not deliver %s; got %v", want, files)
		}
	}
	if len(files) != 3 {
		t.Errorf("expected exactly the 3 selected files, got %d: %v", len(files), files)
	}
}

// 922110 must ship DISABLED. It is the one rule in the multipart family that
// hard-blocks a single match — `block` on its chain starter, no anomaly-score
// contribution — and CRS's allowed-charset list is only four entries wide.
// Measured against the shipped rule, us-ascii, utf-16, shift_jis and euc-kr are
// all refused outright, so leaving it enabled would reject ordinary uploads from
// any customer serving Japanese or Korean content.
//
// The other two 922 rules stay active, so this test also guards against someone
// "fixing" the false positive by disabling the whole multipart category.
func TestMultipartCharsetPolicyRuleIsDisabledByDefault(t *testing.T) {
	waf, err := buildRustWaf(json.RawMessage(`{"mode":"blocking"}`))
	if err != nil {
		t.Fatalf("buildRustWaf: %v", err)
	}
	ex, _ := waf["rule_exclusions"].([]map[string]any)
	found := false
	for _, e := range ex {
		if ruleIDEquals(e["rule_id"], 922110) {
			if dis, _ := e["disable"].(bool); dis {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("922110 must be disabled by default — it hard-blocks any part "+
			"Content-Type charset outside CRS's four-entry allow list "+
			"(us-ascii, utf-16, shift_jis, euc-kr all refused). Got %v", ex)
	}

	// And the category itself must still be delivered, with its safe rules.
	files := crsFilesForCategories(nil)
	joined := strings.Join(files, " ")
	if !strings.Contains(joined, "REQUEST-922-MULTIPART-ATTACK.conf") {
		t.Errorf("the multipart family must still load by default (922120/922130 "+
			"are score-contributing and measured clean); got %v", files)
	}
}
