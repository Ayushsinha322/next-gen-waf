// Package settings is the registry of node-wide values an operator may change
// from the console, and the resolution order for each: an operator-set value in
// the database wins, then the control plane's environment, then the built-in
// default. Every resolved value carries its source so the page can show WHY a
// number is what it is.
//
// Only keys listed here are accepted by the API. A subsystem that wants a
// console-editable knob adds a Key with a validator and reads it through a
// Resolver at its refresh tick; nothing here reaches into subsystems.
package settings

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Type is the JSON shape a key accepts.
type Type string

const (
	Int    Type = "int"
	Bool   Type = "bool"
	String Type = "string"
)

// Key describes one editable global setting.
type Key struct {
	Name        string `json:"key"`
	Group       string `json:"group"`
	Type        Type   `json:"type"`
	Description string `json:"description"`
	// Env is the environment variable that used to be the only way to set it.
	Env string `json:"env,omitempty"`
	// Default is the built-in value when neither DB nor env sets it.
	Default any `json:"default"`
	// Applies says how a change takes effect: "live" (next refresh tick,
	// within a minute) — this registry holds nothing that needs a restart.
	Applies string `json:"applies"`
	// Unit is a display hint: "seconds", "requests", "url".
	Unit string `json:"unit,omitempty"`
	// Min/Max bound ints. A Min of -1 permits the "disabled" sentinel.
	Min, Max int64
	// Validate may reject a value with a human-readable reason.
	Validate func(v any) error `json:"-"`
}

// Registry is every key the console may edit, in display order.
var Registry = []Key{
	// ---- Alerting --------------------------------------------------------
	{Name: "alerting.window_secs", Group: "alerting", Type: Int, Unit: "seconds", Min: 5, Max: 3600, Default: 60, Applies: "live",
		Env: "SENTINEL_ALERT_WINDOW_SECS", Description: "Sliding window over which blocks are counted for spike and repeat-offender alerts."},
	{Name: "alerting.spike_threshold", Group: "alerting", Type: Int, Unit: "blocks", Min: 1, Max: 100000, Default: 20, Applies: "live",
		Env: "SENTINEL_ALERT_SPIKE_THRESHOLD", Description: "Blocks on one site within the window that raise an attack_spike alert."},
	{Name: "alerting.offender_threshold", Group: "alerting", Type: Int, Unit: "blocks", Min: 1, Max: 100000, Default: 15, Applies: "live",
		Env: "SENTINEL_ALERT_OFFENDER_THRESHOLD", Description: "Blocks from one source IP within the window that raise a repeat_offender alert."},
	{Name: "alerting.throttle_secs", Group: "alerting", Type: Int, Unit: "seconds", Min: 10, Max: 86400, Default: 300, Applies: "live",
		Env: "SENTINEL_ALERT_THROTTLE_SECS", Description: "Minimum time between two alerts for the same condition (same kind, site and source)."},
	{Name: "alerting.auto_resolve_secs", Group: "alerting", Type: Int, Unit: "seconds", Min: -1, Max: 604800, Default: 1800, Applies: "live",
		Env: "SENTINEL_ALERT_AUTORESOLVE_SECS", Description: "Close an attack alert that has not recurred for this long. -1 disables auto-resolve.",
		Validate: func(v any) error {
			n := v.(int64)
			if n != -1 && n < 60 {
				return fmt.Errorf("must be -1 (disabled) or at least 60 seconds")
			}
			return nil
		}},
	// ---- Threat intelligence --------------------------------------------
	{Name: "threat_intel.enabled", Group: "threat_intel", Type: Bool, Default: true, Applies: "live",
		Env: "SENTINEL_THREATINTEL_ENABLED", Description: "Fetch external indicator feeds. Indicators already in the corpus stay enforced when off."},
	{Name: "threat_intel.interval_secs", Group: "threat_intel", Type: Int, Unit: "seconds", Min: 300, Max: 86400, Default: 3600, Applies: "live",
		Env: "SENTINEL_THREATINTEL_INTERVAL", Description: "How often every feed is re-fetched."},
	{Name: "threat_intel.feed.tor", Group: "threat_intel", Type: String, Unit: "url", Default: "https://check.torproject.org/torbulkexitlist", Applies: "live",
		Env: "SENTINEL_TI_TOR_URL", Description: "Tor exit-node list (watch tier). Set to 'off' to disable this feed.", Validate: urlOrOff},
	{Name: "threat_intel.feed.feodo", Group: "threat_intel", Type: String, Unit: "url", Default: "https://feodotracker.abuse.ch/downloads/ipblocklist.json", Applies: "live",
		Env: "SENTINEL_TI_FEODO_URL", Description: "abuse.ch Feodo Tracker botnet C2 IPs (block tier). 'off' disables.", Validate: urlOrOff},
	{Name: "threat_intel.feed.urlhaus", Group: "threat_intel", Type: String, Unit: "url", Default: "https://urlhaus.abuse.ch/downloads/text/", Applies: "live",
		Env: "SENTINEL_TI_URLHAUS_URL", Description: "abuse.ch URLhaus malware-distribution domains (block tier). 'off' disables.", Validate: urlOrOff},
	{Name: "threat_intel.feed.stix", Group: "threat_intel", Type: String, Unit: "url", Default: "", Applies: "live",
		Env: "SENTINEL_TI_STIX_URL", Description: "A STIX 2.1 bundle URL from your own CTI platform. Empty or 'off' disables.", Validate: urlOrOff},
}

func urlOrOff(v any) error {
	s := strings.TrimSpace(v.(string))
	if s == "" || s == "off" || s == "-" {
		return nil
	}
	if !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://") {
		return fmt.Errorf("must be an http(s) URL, 'off' or empty")
	}
	return nil
}

// Lookup finds a registry key by name.
func Lookup(name string) (Key, bool) {
	for _, k := range Registry {
		if k.Name == name {
			return k, true
		}
	}
	return Key{}, false
}

// Effective is one resolved value with provenance.
type Effective struct {
	Key
	Value     any        `json:"value"`
	Source    string     `json:"source"` // "db" | "env" | "default"
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy *string    `json:"updated_by,omitempty"`
}

// Override is a DB row as the resolver sees it.
type Override struct {
	Value     json.RawMessage
	UpdatedAt time.Time
	UpdatedBy *string
}

// Resolve computes every key's effective value from the DB overrides (may be
// nil), the process environment, and the defaults. Deterministic order.
func Resolve(overrides map[string]Override) []Effective {
	out := make([]Effective, 0, len(Registry))
	for _, k := range Registry {
		e := Effective{Key: k, Value: k.Default, Source: "default"}
		if k.Env != "" {
			if raw, ok := os.LookupEnv(k.Env); ok && strings.TrimSpace(raw) != "" {
				if v, err := parseEnv(k, raw); err == nil {
					e.Value, e.Source = v, "env"
				}
			}
		}
		if o, ok := overrides[k.Name]; ok {
			if v, err := Coerce(k, o.Value); err == nil {
				e.Value, e.Source = v, "db"
				t := o.UpdatedAt
				e.UpdatedAt, e.UpdatedBy = &t, o.UpdatedBy
			}
		}
		out = append(out, e)
	}
	return out
}

// Coerce parses and validates a JSON value against the key's type and bounds.
// Returns the normalised Go value (int64 / bool / string).
func Coerce(k Key, raw json.RawMessage) (any, error) {
	switch k.Type {
	case Int:
		var n json.Number
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, fmt.Errorf("%s: expected an integer", k.Name)
		}
		i, err := n.Int64()
		if err != nil {
			return nil, fmt.Errorf("%s: expected an integer", k.Name)
		}
		if i < k.Min || i > k.Max {
			return nil, fmt.Errorf("%s: must be between %d and %d", k.Name, k.Min, k.Max)
		}
		if k.Validate != nil {
			if err := k.Validate(i); err != nil {
				return nil, fmt.Errorf("%s: %v", k.Name, err)
			}
		}
		return i, nil
	case Bool:
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, fmt.Errorf("%s: expected true or false", k.Name)
		}
		return b, nil
	case String:
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("%s: expected a string", k.Name)
		}
		s = strings.TrimSpace(s)
		if len(s) > 2048 {
			return nil, fmt.Errorf("%s: too long", k.Name)
		}
		if k.Validate != nil {
			if err := k.Validate(s); err != nil {
				return nil, fmt.Errorf("%s: %v", k.Name, err)
			}
		}
		return s, nil
	}
	return nil, fmt.Errorf("%s: unknown type", k.Name)
}

func parseEnv(k Key, raw string) (any, error) {
	raw = strings.TrimSpace(raw)
	switch k.Type {
	case Int:
		// Durations in env are seconds for *_SECS keys but the threat-intel
		// interval was a Go duration string ("1h"); accept both.
		if d, err := time.ParseDuration(raw); err == nil && strings.ContainsAny(raw, "hms") {
			return Coerce(k, json.RawMessage(strconv.FormatInt(int64(d/time.Second), 10)))
		}
		return Coerce(k, json.RawMessage(raw))
	case Bool:
		switch strings.ToLower(raw) {
		case "1", "true", "yes", "on":
			return true, nil
		case "0", "false", "no", "off":
			return false, nil
		}
		return nil, fmt.Errorf("bad bool")
	default:
		return Coerce(k, json.RawMessage(strconv.Quote(raw)))
	}
}

// Values is a resolved snapshot with typed accessors for subsystems.
type Values map[string]any

// Snapshot indexes Resolve's output by key.
func Snapshot(overrides map[string]Override) Values {
	v := Values{}
	for _, e := range Resolve(overrides) {
		v[e.Name] = e.Value
	}
	return v
}

func (v Values) Int(name string) int64 {
	switch x := v[name].(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	}
	return 0
}
func (v Values) Bool(name string) bool     { b, _ := v[name].(bool); return b }
func (v Values) String(name string) string { s, _ := v[name].(string); return s }
func (v Values) Duration(name string) time.Duration {
	return time.Duration(v.Int(name)) * time.Second
}

// Groups returns the distinct group names in registry order.
func Groups() []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range Registry {
		if !seen[k.Group] {
			seen[k.Group] = true
			out = append(out, k.Group)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return false })
	return out
}
