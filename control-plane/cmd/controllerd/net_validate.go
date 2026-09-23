package main

import (
	"fmt"
	"net"
	"strings"
)

// isoCountryCodes is every ISO 3166-1 alpha-2 code, plus XK (Kosovo), which
// DB-IP and MaxMind both assign. The GeoIP module compares codes by exact
// (uppercased) match, so a code outside this set can never match a request —
// "USA" was accepted, shown as applied, and blocked nothing.
//
// Mirrored by ISO_COUNTRY_CODES in dashboard/lib/netValidate.ts; a console test
// fails if the two lists drift.
const isoCountryCodes = `
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL
BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV
CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD
GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM
IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK
LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW
MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR
PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS
ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY
UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW XK
`

var isoCountrySet = func() map[string]bool {
	m := map[string]bool{}
	for _, c := range strings.Fields(isoCountryCodes) {
		m[c] = true
	}
	return m
}()

// countryHints maps the mistakes operators actually make to the code they meant.
var countryHints = map[string]string{
	"UK": "GB", "USA": "US", "GBR": "GB", "IND": "IN", "CHN": "CN", "RUS": "RU",
	"DEU": "DE", "FRA": "FR", "PAK": "PK", "BGD": "BD", "NPL": "NP", "LKA": "LK",
	"ARE": "AE", "SAU": "SA", "SGP": "SG", "JPN": "JP", "KOR": "KR", "PRK": "KP",
	"BRA": "BR", "CAN": "CA", "AUS": "AU", "IRN": "IR", "TUR": "TR", "UKR": "UA",
}

// countryCodeProblem says what is wrong with one list entry, or "" if nothing.
func countryCodeProblem(code string) string {
	c := strings.ToUpper(strings.TrimSpace(code))
	if isoCountrySet[c] {
		return ""
	}
	if hint, ok := countryHints[c]; ok {
		return fmt.Sprintf("%q is not a country code this WAF can match — did you mean %q? Codes are ISO 3166-1 two-letter codes", code, hint)
	}
	return fmt.Sprintf("%q is not an ISO 3166-1 two-letter country code, so it can never match a request", code)
}

// ipEntryProblem accepts what the data plane accepts: a bare address (one host)
// or a CIDR range, IPv4 or IPv6.
func ipEntryProblem(entry string) string {
	e := strings.TrimSpace(entry)
	if net.ParseIP(e) != nil {
		return ""
	}
	if _, _, err := net.ParseCIDR(e); err == nil {
		return ""
	}
	return fmt.Sprintf("%q is not an IP address or CIDR range (e.g. 203.0.113.7 or 10.0.0.0/8)", entry)
}
