package main

import (
	"testing"
	"time"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

func iocAt(typ, value string, conf int, seen time.Time) db.IOC {
	return db.IOC{Type: typ, Value: value, Confidence: conf, LastSeen: seen}
}

// Deleting or expiring an indicator must change what nodes see as the corpus
// version, or they never reload and keep enforcing it. The version used to be
// the newest last_seen, which removing an older indicator never moves.
func TestCorpusVersionChangesWhenAnIndicatorIsWithdrawn(t *testing.T) {
	t0 := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	all := []db.IOC{
		iocAt("ip", "203.0.113.7", 90, t0),
		iocAt("ip", "198.51.100.9", 90, t0.Add(-time.Hour)),
		iocAt("domain", "evil.example", 60, t0.Add(-2*time.Hour)),
	}
	withdrawn := []db.IOC{all[0], all[2]} // the older IP deleted (or expired)

	oldVersion := func(iocs []db.IOC) int64 {
		var v int64
		for _, i := range iocs {
			if ts := i.LastSeen.Unix(); ts > v {
				v = ts
			}
		}
		return v
	}
	if oldVersion(all) != oldVersion(withdrawn) {
		t.Fatal("test premise: the old max(last_seen) version must not move on this delete")
	}

	if corpusVersion(all, 80) == corpusVersion(withdrawn, 80) {
		t.Fatal("withdrawing an indicator left the corpus version unchanged — nodes would keep enforcing it")
	}
}

func TestCorpusVersionIsOrderIndependentAndTierAware(t *testing.T) {
	t0 := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	a := iocAt("ip", "203.0.113.7", 90, t0)
	b := iocAt("cidr", "198.51.100.0/24", 85, t0)
	if corpusVersion([]db.IOC{a, b}, 80) != corpusVersion([]db.IOC{b, a}, 80) {
		t.Fatal("the same corpus in a different row order must have the same version")
	}
	// A confidence change that moves an indicator between block and watch is
	// a different enforcement, so a different version.
	if corpusVersion([]db.IOC{a, b}, 80) == corpusVersion([]db.IOC{a, b}, 88) {
		t.Fatal("moving an indicator from block to watch must change the version")
	}
	if v := corpusVersion(nil, 80); v < 0 {
		t.Fatalf("version must be non-negative, got %d", v)
	}
	if corpusVersion(nil, 80) == corpusVersion([]db.IOC{a}, 80) {
		t.Fatal("an empty corpus and a non-empty one must differ")
	}
}
