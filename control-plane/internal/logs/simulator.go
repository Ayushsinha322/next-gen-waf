package logs

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"time"
)

// SimulatorEnvVar must be set to "1" for the simulator to be allowed to run.
const SimulatorEnvVar = "SENTINEL_DEV_SIMULATOR"

// SimulatorEnabled reports whether the operator has explicitly opted in to
// fabricated log data.
//
// This is an explicit opt-in, not a fallback. The simulator used to start
// automatically whenever the Rust data-plane binary was missing, so a control
// plane that simply could not find its proxy would invent attacks — realistic
// IPs, CVE references, block verdicts — and stream them to the dashboard through
// the same code path as real traffic. An operator or a client seeing that screen
// had no way to know none of it happened. Absent data must read as absent, so the
// default is now to publish nothing.
func SimulatorEnabled() bool {
	return os.Getenv(SimulatorEnvVar) == "1"
}

// StartSimulator launches a background goroutine that publishes FABRICATED log
// entries into the hub. Every entry it emits is tagged Source=simulated.
//
// It is a no-op unless SENTINEL_DEV_SIMULATOR=1. Returns whether it started, so
// callers can log accurately. The goroutine exits when the hub is stopped.
func (h *Hub) StartSimulator() bool {
	if !SimulatorEnabled() {
		return false
	}
	go h.runSimulator()
	return true
}

func (h *Hub) runSimulator() {
	accessT := time.NewTicker(280 * time.Millisecond)
	wafT := time.NewTicker(1800 * time.Millisecond)
	errorT := time.NewTicker(6500 * time.Millisecond)
	modsecT := time.NewTicker(3200 * time.Millisecond)
	mlT := time.NewTicker(5000 * time.Millisecond)
	auditT := time.NewTicker(12 * time.Second)
	defer func() {
		accessT.Stop()
		wafT.Stop()
		errorT.Stop()
		modsecT.Stop()
		mlT.Stop()
		auditT.Stop()
	}()

	for {
		select {
		case <-h.done:
			return
		case <-accessT.C:
			h.simPublish("access", simAccess())
		case <-wafT.C:
			h.simPublish("waf", simWAF())
		case <-errorT.C:
			h.simPublish("error", simError())
		case <-modsecT.C:
			h.simPublish("modsec", simModsec())
		case <-mlT.C:
			h.simPublish("ml", simML())
		case <-auditT.C:
			h.simPublish("audit", simAudit())
		}
	}
}

func (h *Hub) simPublish(kind string, data map[string]any) {
	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	// Every simulated entry is tagged at the source. Nothing this file produces
	// may ever be presented as observed traffic.
	h.publish(Entry{Kind: kind, Data: json.RawMessage(raw), Source: SourceSimulated})
}

// ---------------------------------------------------------------------------
// Sample data pools
// ---------------------------------------------------------------------------

var simIPs = []string{
	"185.220.101.45", "103.24.8.122", "91.240.118.150", "198.235.24.130",
	"10.0.0.45", "172.16.1.100", "45.33.32.156", "203.0.113.42",
	"198.51.100.7", "5.188.206.14", "194.165.16.32", "77.247.108.22",
	"62.210.218.209", "185.100.87.174", "192.241.245.18",
}

var simPaths = []string{
	"/api/v1/login", "/api/v2/products", "/search", "/admin/users",
	"/api/orders", "/static/app.js", "/api/v1/auth/refresh", "/health",
	"/api/v3/payments", "/wp-admin/", "/.git/config", "/api/v1/config",
	"/api/v1/users", "/admin/config", "/phpmyadmin/", "/api/graphql",
	"/actuator/env", "/api/v1/reports", "/.env", "/api/v2/checkout",
}

var simSites = []string{
	"juice.local", "dvwa.local", "api.acme.com", "shop.corp.io", "intranet.corp.io",
}

var simMethods = []string{
	"GET", "GET", "GET", "POST", "POST", "PUT", "DELETE", "GET", "POST",
}

var simAttacks = []string{
	"sql_injection", "xss", "path_traversal", "command_injection",
	"log4shell", "xxe", "ssrf", "lfi", "rfi", "scanner", "brute_force",
}

var simRules = []string{
	"CRS-942100", "CRS-941100", "CRS-930100", "CRS-932100",
	"CRS-913100", "CRS-920270", "VP-CVE-2021-44228", "CRS-941140",
	"CRS-932160", "CRS-920420", "CRS-949110", "VP-CVE-2024-3094",
}

var simWAFMsgs = []string{
	"SQL injection via libinjection detected",
	"XSS attack detected via libinjection",
	"Path traversal attack (/../) detected",
	"Remote command execution — direct Unix command",
	"Found User-Agent associated with security scanner",
	"Log4Shell JNDI injection attempt",
	"Invalid character in request (null byte)",
	"Inbound anomaly score exceeded threshold",
	"XXE payload detected in request body",
	"SSRF attempt via URL parameter",
}

var simSubsystems = []string{
	"proxy", "rules", "ml", "cluster", "auth", "storage", "grpc", "ebpf",
}

var simErrorMsgs = []string{
	"upstream connection timeout after 5000ms",
	"failed to acquire DB connection from pool",
	"rule engine: bytecode verification failed",
	"ML model inference latency exceeded 50ms",
	"Redis cache miss rate above 80% threshold",
	"gRPC config push: subscriber disconnect",
	"eBPF program load failed: permission denied",
	"TLS handshake timeout from 185.220.101.45",
}

var simModsecMsgs = []string{
	"SQL Injection Attack Detected via libinjection",
	"XSS Attack Detected via libinjection",
	"Remote File Inclusion Attack",
	"OS Command Injection",
	"Remote Code Execution — JNDI injection",
	"Scanner User-Agent Detected",
	"Invalid protocol anomaly",
	"Inbound anomaly score exceeded",
}

var simModsecCats = []string{
	"SQLI", "XSS", "RFI", "RCE", "SCANNER", "PROTOCOL", "ANOMALY",
}

var simMLModels = []string{
	"payload-classifier-v2", "isolation-forest-v3", "xgboost-anomaly-v1",
	"candle-transformer-v1", "onnx-embedding-v2",
}

var simMLLabels = []string{
	"sqli_pattern", "xss_pattern", "path_traversal", "benign",
	"scanner_signature", "brute_force_attempt", "c2_traffic", "benign",
}

var simMLVerdicts = []string{
	"ANOMALY_BLOCKED", "BENIGN", "BENIGN", "ANOMALY_WARN", "BENIGN",
	"SCAN_DETECT", "BRUTE_FORCE", "BENIGN", "BENIGN", "EXFIL_SUSPECT",
}

var simAuditUsers = []string{
	"admin@sentinel.local", "raj@sentinel.local", "priya@sentinel.local",
	"api-key:sk-live-f87a48c6", "system",
}

var simAuditActions = []string{
	"rule.enable", "rule.disable", "site.mode_change", "user.login",
	"config.update", "apikey.create", "alert.resolve", "alert.ack",
	"site.create", "plugin.install",
}

var simAuditResources = []string{
	"CRS-942100", "site:dvwa.local", "user:raj", "config:waf.mode",
	"apikey:CI/CD", "alert:uuid-xxx", "plugin:jwt-validator",
}

// ---------------------------------------------------------------------------
// Entry generators
// ---------------------------------------------------------------------------

var simUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
	"sqlmap/1.8.2#stable (https://sqlmap.org)",
	"Nikto/2.1.6",
	"python-requests/2.31.0",
	"curl/8.6.0",
	"Go-http-client/1.1",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
}

func simAccess() map[string]any {
	ip := simIPs[rand.Intn(len(simIPs))]
	path := simPaths[rand.Intn(len(simPaths))]
	method := simMethods[rand.Intn(len(simMethods))]
	site := simSites[rand.Intn(len(simSites))]
	ua := simUserAgents[rand.Intn(len(simUserAgents))]

	var status int
	var action string
	if rand.Float32() < 0.05 {
		status = 403
		action = "BLOCKED"
	} else {
		pick := []int{200, 200, 200, 302, 404, 500}
		status = pick[rand.Intn(len(pick))]
		action = "PASS"
	}

	latency := fmt.Sprintf("%.2f", 0.05+rand.Float64()*2.5)
	bytes := rand.Intn(50000) + 200
	score := 0
	if status == 403 {
		score = rand.Intn(30) + 5
	}

	return map[string]any{
		"ts":      now(),
		"method":  method,
		"path":    path,
		"status":  status,
		"latency": latency,
		"ip":      ip,
		"site":    site,
		"bytes":   bytes,
		"score":   score,
		"action":  action,
		"ua":      ua,
	}
}

var simSevLevels = []string{"CRITICAL", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW"}

func simWAF() map[string]any {
	ip := simIPs[rand.Intn(len(simIPs))]
	path := simPaths[rand.Intn(len(simPaths))]
	method := simMethods[rand.Intn(len(simMethods))]
	site := simSites[rand.Intn(len(simSites))]
	attack := simAttacks[rand.Intn(len(simAttacks))]
	rule := simRules[rand.Intn(len(simRules))]
	msg := simWAFMsgs[rand.Intn(len(simWAFMsgs))]
	sev := simSevLevels[rand.Intn(len(simSevLevels))]

	action := "BLOCKED"
	if rand.Float32() > 0.75 {
		action = "LOGGED"
	}

	return map[string]any{
		"ts":     now(),
		"action": action,
		"rule":   rule,
		"attack": attack,
		"score":  rand.Intn(40) + 5,
		"ip":     ip,
		"path":   path,
		"site":   site,
		"method": method,
		"msg":    msg,
		"sev":    sev,
	}
}

func simError() map[string]any {
	lvls := []string{"WARN", "WARN", "ERROR", "ERROR", "FATAL"}
	lvl := lvls[rand.Intn(len(lvls))]
	return map[string]any{
		"ts":        now(),
		"lvl":       lvl,
		"msg":       simErrorMsgs[rand.Intn(len(simErrorMsgs))],
		"subsystem": simSubsystems[rand.Intn(len(simSubsystems))],
		"site":      simSites[rand.Intn(len(simSites))],
	}
}

func simModsec() map[string]any {
	rule := simRules[rand.Intn(len(simRules))]
	msg := simModsecMsgs[rand.Intn(len(simModsecMsgs))]
	cat := simModsecCats[rand.Intn(len(simModsecCats))]
	phases := []int{1, 2, 2, 3}
	action := "blocked"
	if rand.Float32() > 0.7 {
		action = "logged"
	}
	txID := fmt.Sprintf("tx-%08x", rand.Int63n(0xffffffff))
	return map[string]any{
		"ts":     now(),
		"txId":   txID,
		"ruleId": rule,
		"msg":    msg,
		"sev":    fmt.Sprintf("%d", rand.Intn(4)+1),
		"cat":    cat,
		"phase":  phases[rand.Intn(len(phases))],
		"ip":     simIPs[rand.Intn(len(simIPs))],
		"uri":    simPaths[rand.Intn(len(simPaths))],
		"site":   simSites[rand.Intn(len(simSites))],
		"action": action,
	}
}

func simML() map[string]any {
	verdict := simMLVerdicts[rand.Intn(len(simMLVerdicts))]
	model := simMLModels[rand.Intn(len(simMLModels))]
	label := simMLLabels[rand.Intn(len(simMLLabels))]
	score := rand.Float64()
	if verdict == "BENIGN" {
		score = rand.Float64() * 0.3
	} else {
		score = 0.6 + rand.Float64()*0.4
	}
	features := 12 + rand.Intn(40)
	latency := fmt.Sprintf("%.2f", 0.1+rand.Float64()*2.8)
	return map[string]any{
		"ts":       now(),
		"verdict":  verdict,
		"model":    model,
		"conf":     fmt.Sprintf("%.1f", score*100),
		"label":    label,
		"ip":       simIPs[rand.Intn(len(simIPs))],
		"path":     simPaths[rand.Intn(len(simPaths))],
		"site":     simSites[rand.Intn(len(simSites))],
		"features": features,
		"latency":  latency,
	}
}

func simAudit() map[string]any {
	return map[string]any{
		"ts":       now(),
		"user":     simAuditUsers[rand.Intn(len(simAuditUsers))],
		"action":   simAuditActions[rand.Intn(len(simAuditActions))],
		"resource": simAuditResources[rand.Intn(len(simAuditResources))],
		"ip":       simIPs[rand.Intn(len(simIPs))],
		"result":   "SUCCESS",
		"session":  fmt.Sprintf("sess-%04x", rand.Intn(0xffff)),
	}
}

func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
