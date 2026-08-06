package logs

import "testing"

// The data plane's classify_nonrule_block emits synthetic rule labels for
// non-rule blocks. Three connection-layer labels were added after threat-intel
// and IP-reputation blocks were found being reported as ANOMALY; if this
// mapping is not kept in step they silently roll up as "other" instead.
func TestAttackCategoryConnectionLayerLabels(t *testing.T) {
	for label, want := range map[string]string{
		"THREATINTEL": "threat_intel",
		"IPREP":       "ip_reputation",
		"DDOS":        "ddos",
	} {
		if got := attackCategory(label); got != want {
			t.Fatalf("attackCategory(%q) = %q, want %q", label, got, want)
		}
	}
}

func TestAttackCategoryExistingLabelsUnchanged(t *testing.T) {
	for label, want := range map[string]string{
		"GEOIP":     "geoip",
		"RATELIMIT": "ratelimit",
		"SMUGGLING": "protocol",
		"BOT":       "bot",
		"ANOMALY":   "anomaly",
		"942100":    "sqli",
		"941100":    "xss",
	} {
		if got := attackCategory(label); got != want {
			t.Fatalf("attackCategory(%q) = %q, want %q", label, got, want)
		}
	}
}
