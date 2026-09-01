// mkgeoip-testdb — build a tiny, SYNTHETIC GeoLite2-Country-shaped .mmdb.
//
// Why this exists: country filtering could not be tested end-to-end, because a
// real MaxMind database cannot be committed — MaxMind requires an account and
// its licence forbids redistributing the data inside a third-party product. So
// the enforcement path had no test at all, and "GeoIP works" was an assumption.
//
// This contains NO MaxMind data. It uses MaxMind's mmdbwriter library
// (Apache-2.0) to emit a file in the same format, populated with addresses from
// the documentation/test ranges (RFC 5737, RFC 1918) mapped to arbitrary country
// codes. It is deliberately useless for real geolocation and deliberately
// sufficient to prove that a configured country block actually blocks.
package main

import (
	"log"
	"net"
	"os"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func main() {
	out := "GeoLite2-Country-test.mmdb"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}

	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "GeoLite2-Country",
		// The reader looks up the `country.iso_code` path, so the record shape
		// matters more than the metadata.
		RecordSize: 24,
		// Required, and the reason the first attempt produced no file at all:
		// mmdbwriter refuses reserved networks by default, and every range used
		// here is deliberately reserved — RFC 5737 documentation space and RFC
		// 1918 private space. Using real routable ranges would be worse: the
		// fixture would then assert something about actual addresses.
		IncludeReservedNetworks: true,
	})
	if err != nil {
		log.Fatalf("mmdbwriter.New: %v", err)
	}

	// Documentation and private ranges only. 172.18.0.0/16 is the compose bridge,
	// so a request from inside the test environment resolves to a known country
	// and the block path can be exercised without spoofing anything.
	entries := []struct {
		cidr, iso, name string
	}{
		{"203.0.113.0/24", "CN", "China"},        // RFC 5737 TEST-NET-3
		{"198.51.100.0/24", "RU", "Russia"},      // RFC 5737 TEST-NET-2
		{"192.0.2.0/24", "US", "United States"},  // RFC 5737 TEST-NET-1
		{"172.18.0.0/16", "CN", "China"},         // docker compose bridge
		{"10.0.0.0/8", "GB", "United Kingdom"},
	}

	for _, e := range entries {
		_, network, err := net.ParseCIDR(e.cidr)
		if err != nil {
			log.Fatalf("bad cidr %s: %v", e.cidr, err)
		}
		rec := mmdbtype.Map{
			"country": mmdbtype.Map{
				"iso_code": mmdbtype.String(e.iso),
				"names":    mmdbtype.Map{"en": mmdbtype.String(e.name)},
			},
		}
		if err := w.Insert(network, rec); err != nil {
			log.Fatalf("insert %s: %v", e.cidr, err)
		}
	}

	f, err := os.Create(out)
	if err != nil {
		log.Fatalf("create %s: %v", out, err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		log.Fatalf("write: %v", err)
	}
	log.Printf("wrote %s with %d networks", out, len(entries))
}
