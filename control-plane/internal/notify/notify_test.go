package notify

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func sampleAlert() Alert {
	return Alert{
		ID: "a1", Severity: "critical", Kind: "sqli", Summary: "SQLi blocked",
		Site: "dvwa.local", SourceIP: "203.0.113.5", Rule: "942100", Count: 3,
		CreatedAt: time.Unix(1750000000, 0),
	}
}

func TestSeverityGate(t *testing.T) {
	if !SeverityAtLeast("critical", "low") {
		t.Fatal("critical should pass a low gate")
	}
	if SeverityAtLeast("low", "high") {
		t.Fatal("low must not pass a high gate")
	}
	if !SeverityAtLeast("high", "high") {
		t.Fatal("equal severity should pass")
	}
}

func TestWebhookDeliversSignedJSON(t *testing.T) {
	var gotBody []byte
	var gotSig, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-Sentinel-Signature")
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ch := Channel{ID: "c1", Name: "wh", Type: "webhook", MinSeverity: "low",
		Config: Config{URL: srv.URL, Secret: "s3cr3t"}}
	d := &Dispatcher{}
	res := d.Dispatch(context.Background(), sampleAlert(), []Channel{ch})
	if len(res) != 1 || !res[0].OK {
		t.Fatalf("expected one OK result, got %+v", res)
	}
	if gotCT != "application/json" {
		t.Fatalf("content-type = %q", gotCT)
	}
	if !strings.HasPrefix(gotSig, "sha256=") {
		t.Fatalf("expected HMAC signature header, got %q", gotSig)
	}
	var env struct {
		Event string `json:"event"`
		Alert Alert  `json:"alert"`
	}
	if err := json.Unmarshal(gotBody, &env); err != nil {
		t.Fatalf("body not valid JSON: %v", err)
	}
	if env.Event != "alert" || env.Alert.Rule != "942100" {
		t.Fatalf("unexpected payload: %+v", env)
	}
}

func TestWebhookSeverityGateSkips(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ch := Channel{ID: "c1", Type: "webhook", MinSeverity: "critical", Config: Config{URL: srv.URL}}
	low := sampleAlert()
	low.Severity = "low"
	res := (&Dispatcher{}).Dispatch(context.Background(), low, []Channel{ch})
	if len(res) != 0 {
		t.Fatalf("low alert should be gated out, got %+v", res)
	}
	if hit {
		t.Fatal("webhook must not be called when gated")
	}
}

func TestWebhookReports5xxAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	ch := Channel{ID: "c1", Type: "webhook", MinSeverity: "low", Config: Config{URL: srv.URL}}
	res := (&Dispatcher{}).Test(context.Background(), ch, sampleAlert())
	if res.OK || !strings.Contains(res.Err, "500") {
		t.Fatalf("expected 500 error, got %+v", res)
	}
}

func TestSyslogUDPDelivery(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	_, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	var port int
	if _, err := readInt(portStr, &port); err != nil {
		t.Fatalf("port parse: %v", err)
	}

	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 2048)
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, _ := pc.ReadFrom(buf)
		done <- string(buf[:n])
	}()

	ch := Channel{ID: "s1", Type: "syslog", MinSeverity: "low",
		Config: Config{Host: "127.0.0.1", Port: port, Protocol: "udp"}}
	res := (&Dispatcher{}).Test(context.Background(), ch, sampleAlert())
	if !res.OK {
		t.Fatalf("syslog send failed: %v", res.Err)
	}
	select {
	case msg := <-done:
		// RFC 5424: "<PRI>1 TIMESTAMP HOST APP - MSGID - MSG"
		if !strings.HasPrefix(msg, "<") || !strings.Contains(msg, ">1 ") {
			t.Fatalf("not RFC5424 framed: %q", msg)
		}
		// facility local0(16)*8 + critical(2) = 130
		if !strings.HasPrefix(msg, "<130>1 ") {
			t.Fatalf("expected PRI 130 for critical, got: %q", msg)
		}
		if !strings.Contains(msg, "SQLi blocked") {
			t.Fatalf("message body missing: %q", msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no syslog datagram received")
	}
}

func TestCEFOverSyslog(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	_, portStr, _ := net.SplitHostPort(pc.LocalAddr().String())
	var port int
	readInt(portStr, &port)

	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 2048)
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, _ := pc.ReadFrom(buf)
		done <- string(buf[:n])
	}()

	ch := Channel{ID: "cef1", Type: "cef", MinSeverity: "low",
		Config: Config{Host: "127.0.0.1", Port: port, Protocol: "udp"}}
	res := (&Dispatcher{}).Test(context.Background(), ch, sampleAlert())
	if !res.OK {
		t.Fatalf("cef send failed: %v", res.Err)
	}
	msg := <-done
	if !strings.Contains(msg, "CEF:0|Sentinel|WAF|1.0|sqli|SQLi blocked|10|") {
		t.Fatalf("bad CEF header: %q", msg)
	}
	if !strings.Contains(msg, "src=203.0.113.5") || !strings.Contains(msg, "cs2=942100") {
		t.Fatalf("CEF extensions missing: %q", msg)
	}
}

// readInt parses a base-10 int (tiny helper to avoid importing strconv twice).
func readInt(s string, out *int) (int, error) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, &net.AddrError{Err: "bad port", Addr: s}
		}
		n = n*10 + int(r-'0')
	}
	*out = n
	return n, nil
}
