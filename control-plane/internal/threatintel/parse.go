// Package threatintel aggregates Indicators of Compromise (IOCs) from open
// Cyber Threat Intelligence (CTI) feeds into the control-plane database, from
// where the Rust data plane hot-syncs them. It surpasses the static blocklists
// in F5/HaltDOS by continuously ingesting live global feeds (Tor exit nodes,
// abuse.ch Feodo/URLhaus, STIX/TAXII) with per-source TTLs so stale indicators
// self-expire.
package threatintel

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

// Parsers return IOCs with only Type and Value populated (plus an optional
// per-item Confidence override). The aggregator stamps Source, Category,
// Confidence and TTL/ExpiresAt from the owning Source. This keeps parsers pure
// functions of their input bytes — trivially unit-testable.

// parseTorExitList parses the Tor bulk exit list: one IP per line, '#' comments.
func parseTorExitList(body []byte) ([]db.IOC, error) {
	var out []db.IOC
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if net.ParseIP(line) == nil {
			continue
		}
		out = append(out, db.IOC{Type: "ip", Value: line})
	}
	return dedupeIOCs(out), nil
}

// feodoEntry is the subset of an abuse.ch Feodo Tracker ipblocklist.json record
// we consume.
type feodoEntry struct {
	IPAddress string `json:"ip_address"`
	Malware   string `json:"malware"`
	Status    string `json:"status"`
}

// parseFeodoJSON parses abuse.ch Feodo Tracker's ipblocklist.json (botnet C2 IPs).
func parseFeodoJSON(body []byte) ([]db.IOC, error) {
	var entries []feodoEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("feodo: %w", err)
	}
	var out []db.IOC
	for _, e := range entries {
		ip := strings.TrimSpace(e.IPAddress)
		if ip == "" || net.ParseIP(ip) == nil {
			continue
		}
		out = append(out, db.IOC{Type: "ip", Value: ip})
	}
	return dedupeIOCs(out), nil
}

// parseURLhausText parses abuse.ch URLhaus's plaintext feed (one malicious URL
// per line). We reduce each URL to its host: an IP host becomes an "ip" IOC, a
// name host a "domain" IOC. Full URL paths are intentionally dropped — they are
// noisy and long; host reputation is the durable signal.
func parseURLhausText(body []byte) ([]db.IOC, error) {
	var out []db.IOC
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := url.Parse(line)
		if err != nil {
			continue
		}
		host := u.Hostname()
		if host == "" {
			continue
		}
		if net.ParseIP(host) != nil {
			out = append(out, db.IOC{Type: "ip", Value: host})
		} else {
			out = append(out, db.IOC{Type: "domain", Value: strings.ToLower(host)})
		}
	}
	return dedupeIOCs(out), nil
}

// STIX 2.x indicator pattern extractors. STIX patterns look like
//
//	[ipv4-addr:value = '1.2.3.4']
//	[domain-name:value = 'evil.example']
//	[url:value = 'http://evil.example/x']
//
// We pull out the common object properties. This is a pragmatic pattern
// extractor (not a full STIX pattern grammar), sufficient for the flat
// indicator bundles most TAXII 2.1 collections publish.
var (
	stixIPv4   = regexp.MustCompile(`ipv4-addr:value\s*=\s*'([^']+)'`)
	stixIPv6   = regexp.MustCompile(`ipv6-addr:value\s*=\s*'([^']+)'`)
	stixDomain = regexp.MustCompile(`domain-name:value\s*=\s*'([^']+)'`)
	stixURL    = regexp.MustCompile(`url:value\s*=\s*'([^']+)'`)
)

type stixBundle struct {
	Objects []struct {
		Type    string `json:"type"`
		Pattern string `json:"pattern"`
		Revoked bool   `json:"revoked"`
	} `json:"objects"`
}

// parseSTIXBundle parses a STIX 2.x bundle, extracting IOCs from indicator
// pattern strings. IPs with a "/" become CIDRs; URL hosts become domains.
func parseSTIXBundle(body []byte) ([]db.IOC, error) {
	var bundle stixBundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		return nil, fmt.Errorf("stix: %w", err)
	}
	var out []db.IOC
	for _, obj := range bundle.Objects {
		if obj.Type != "indicator" || obj.Revoked || obj.Pattern == "" {
			continue
		}
		for _, m := range stixIPv4.FindAllStringSubmatch(obj.Pattern, -1) {
			out = append(out, ipOrCIDR(m[1])...)
		}
		for _, m := range stixIPv6.FindAllStringSubmatch(obj.Pattern, -1) {
			out = append(out, ipOrCIDR(m[1])...)
		}
		for _, m := range stixDomain.FindAllStringSubmatch(obj.Pattern, -1) {
			out = append(out, db.IOC{Type: "domain", Value: strings.ToLower(m[1])})
		}
		for _, m := range stixURL.FindAllStringSubmatch(obj.Pattern, -1) {
			if u, err := url.Parse(m[1]); err == nil && u.Hostname() != "" {
				out = append(out, db.IOC{Type: "domain", Value: strings.ToLower(u.Hostname())})
			}
		}
	}
	return dedupeIOCs(out), nil
}

// ipOrCIDR classifies a raw address string as an "ip" or "cidr" IOC, or drops
// it if unparseable.
func ipOrCIDR(v string) []db.IOC {
	v = strings.TrimSpace(v)
	if strings.Contains(v, "/") {
		if _, _, err := net.ParseCIDR(v); err == nil {
			return []db.IOC{{Type: "cidr", Value: v}}
		}
		return nil
	}
	if net.ParseIP(v) != nil {
		return []db.IOC{{Type: "ip", Value: v}}
	}
	return nil
}

// dedupeIOCs removes duplicate (type,value) pairs within a single feed's output.
func dedupeIOCs(in []db.IOC) []db.IOC {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, ioc := range in {
		key := ioc.Type + "\x00" + ioc.Value
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ioc)
	}
	return out
}
