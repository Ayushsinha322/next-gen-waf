package threatintel

import "testing"

func TestParseTorExitList(t *testing.T) {
	body := []byte("1.1.1.1\n# comment line\n5.5.5.5\nnot-an-ip\n\n  2.2.2.2  \n1.1.1.1\n")
	iocs, err := parseTorExitList(body)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	// 1.1.1.1, 5.5.5.5, 2.2.2.2 — dedup drops the second 1.1.1.1; comment/blank/invalid skipped.
	if len(iocs) != 3 {
		t.Fatalf("want 3 IOCs, got %d: %+v", len(iocs), iocs)
	}
	for _, i := range iocs {
		if i.Type != "ip" {
			t.Errorf("want type ip, got %q for %q", i.Type, i.Value)
		}
	}
}

func TestParseFeodoJSON(t *testing.T) {
	body := []byte(`[
		{"ip_address":"5.5.5.5","malware":"Emotet","status":"online"},
		{"ip_address":"9.9.9.9","malware":"Dridex","status":"online"},
		{"ip_address":"","malware":"x"},
		{"ip_address":"garbage","malware":"y"}
	]`)
	iocs, err := parseFeodoJSON(body)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(iocs) != 2 {
		t.Fatalf("want 2 IOCs, got %d: %+v", len(iocs), iocs)
	}
}

func TestParseFeodoJSON_BadJSON(t *testing.T) {
	if _, err := parseFeodoJSON([]byte("not json")); err == nil {
		t.Fatal("want error for bad JSON")
	}
}

func TestParseURLhausText(t *testing.T) {
	body := []byte("# URLhaus dump\n" +
		"http://evil.example.com/a.exe\n" +
		"https://evil.example.com/b.bin\n" + // same host → dedup to one domain
		"http://203.0.113.7/payload\n" + // IP host → ip IOC
		"garbage line without scheme\n")
	iocs, err := parseURLhausText(body)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	var domains, ips int
	for _, i := range iocs {
		switch i.Type {
		case "domain":
			domains++
			if i.Value != "evil.example.com" {
				t.Errorf("unexpected domain %q", i.Value)
			}
		case "ip":
			ips++
			if i.Value != "203.0.113.7" {
				t.Errorf("unexpected ip %q", i.Value)
			}
		}
	}
	if domains != 1 || ips != 1 {
		t.Fatalf("want 1 domain + 1 ip, got %d domains %d ips: %+v", domains, ips, iocs)
	}
}

func TestParseSTIXBundle(t *testing.T) {
	body := []byte(`{
	  "type":"bundle",
	  "objects":[
	    {"type":"indicator","pattern":"[ipv4-addr:value = '198.51.100.9']"},
	    {"type":"indicator","pattern":"[ipv4-addr:value = '10.0.0.0/8']"},
	    {"type":"indicator","pattern":"[domain-name:value = 'BadDomain.Example']"},
	    {"type":"indicator","pattern":"[url:value = 'http://c2.example/beacon']"},
	    {"type":"indicator","revoked":true,"pattern":"[ipv4-addr:value = '1.2.3.4']"},
	    {"type":"malware","name":"x"}
	  ]
	}`)
	iocs, err := parseSTIXBundle(body)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	got := map[string]string{}
	for _, i := range iocs {
		got[i.Value] = i.Type
	}
	if got["198.51.100.9"] != "ip" {
		t.Errorf("want ip for 198.51.100.9, got %q", got["198.51.100.9"])
	}
	if got["10.0.0.0/8"] != "cidr" {
		t.Errorf("want cidr for 10.0.0.0/8, got %q", got["10.0.0.0/8"])
	}
	if got["baddomain.example"] != "domain" { // lowercased
		t.Errorf("want lowercased domain, got %+v", got)
	}
	if got["c2.example"] != "domain" { // url → host
		t.Errorf("want domain from url host, got %+v", got)
	}
	if _, ok := got["1.2.3.4"]; ok {
		t.Errorf("revoked indicator must be skipped")
	}
}
