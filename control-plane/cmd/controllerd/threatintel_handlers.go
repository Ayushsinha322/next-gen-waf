package main

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

// defaultBlockConfidence is the confidence at/above which an IOC is enforced as
// a hard block; below it, the IOC only contributes to the anomaly score.
// Tunable via SENTINEL_TI_BLOCK_CONFIDENCE.
const defaultBlockConfidence = 80

// threatIntelTier is one enforcement tier's IOCs grouped by type, so the Rust
// enforcer can build its IP matcher + lookup sets directly.
type threatIntelTier struct {
	IPs           []string `json:"ips"`
	CIDRs         []string `json:"cidrs"`
	UserAgents    []string `json:"user_agents"`
	Domains       []string `json:"domains"`
	URLSubstrings []string `json:"url_substrings"`
}

func newTier() threatIntelTier {
	return threatIntelTier{
		IPs:           []string{},
		CIDRs:         []string{},
		UserAgents:    []string{},
		Domains:       []string{},
		URLSubstrings: []string{},
	}
}

// add routes one IOC value into the correct type bucket of this tier.
func (t *threatIntelTier) add(iocType, value string) {
	switch iocType {
	case "ip":
		t.IPs = append(t.IPs, value)
	case "cidr":
		t.CIDRs = append(t.CIDRs, value)
	case "user_agent":
		t.UserAgents = append(t.UserAgents, value)
	case "domain":
		t.Domains = append(t.Domains, value)
	case "url_substring":
		t.URLSubstrings = append(t.URLSubstrings, value)
	}
}

// threatIntelResponse is the optimized, deduplicated IOC snapshot the Rust data
// plane hot-syncs. IOCs are pre-split into a high-confidence block tier and a
// lower-confidence watch tier so enforcement policy lives in one place (here).
// Version is the epoch of the newest last_seen so the poller skips a rebuild
// when nothing changed.
type threatIntelResponse struct {
	Version         int64           `json:"version"`
	GeneratedAt     string          `json:"generated_at"`
	Count           int             `json:"count"`
	BlockConfidence int             `json:"block_confidence"`
	Block           threatIntelTier `json:"block"`
	Watch           threatIntelTier `json:"watch"`
}

// blockConfidenceThreshold reads the block/watch cutoff from the environment.
func blockConfidenceThreshold() int {
	if v := os.Getenv("SENTINEL_TI_BLOCK_CONFIDENCE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 100 {
			return n
		}
	}
	return defaultBlockConfidence
}

// handleInternalThreatIntel serves the active IOC set to the data-plane poller.
// Gated by the shared internal secret (not JWT), like handleInternalConfig:
// exposing the REST port must not leak the threat-intel corpus. Node-global
// (IOCs are not tenant-scoped).
func handleInternalThreatIntel(c *gin.Context, store *db.Store) {
	if !internalSecretOK(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "db unavailable"})
		return
	}
	iocs, err := store.ListActiveIOCs(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	threshold := blockConfidenceThreshold()
	resp := threatIntelResponse{
		Count:           len(iocs),
		BlockConfidence: threshold,
		Block:           newTier(),
		Watch:           newTier(),
	}
	var version int64
	for _, ioc := range iocs {
		if ts := ioc.LastSeen.Unix(); ts > version {
			version = ts
		}
		if ioc.Confidence >= threshold {
			resp.Block.add(ioc.Type, ioc.Value)
		} else {
			resp.Watch.add(ioc.Type, ioc.Value)
		}
	}
	resp.Version = version
	resp.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	c.JSON(http.StatusOK, resp)
}
