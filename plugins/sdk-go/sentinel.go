// Package sentinel provides the Go guest SDK for building Sentinel WAF WASM
// plugins.  Plugins are compiled with TinyGo (`tinygo build -target wasm`).
//
// # Quick start
//
//	package main
//
//	import "github.com/sentinel-waf/plugin-sdk-go"
//
//	//export evaluate
//	func evaluate() {
//	    sentinel.Log("Hello from Go plugin!")
//	    ua := sentinel.GetReqHeader("user-agent")
//	    if ua != "" && sentinel.Contains(ua, "sqlmap") {
//	        sentinel.SetDecision(sentinel.DecisionBlock)
//	    }
//	}
//
//	func main() {}
package sentinel

// ---------------------------------------------------------------------------
// WASM imports — these are provided by the Sentinel host at runtime
// ---------------------------------------------------------------------------

//go:wasmimport env host_log
func hostLog(ptr *byte, length int32)

//go:wasmimport env host_get_req_header
func hostGetReqHeader(namePtr *byte, nameLen int32, outPtr *byte, outMaxLen int32) int32

//go:wasmimport env host_set_decision
func hostSetDecision(code int32)

//go:wasmimport env host_add_score
func hostAddScore(delta int32)

//go:wasmimport env host_set_header
func hostSetHeader(namePtr *byte, nameLen int32, valPtr *byte, valLen int32)

//go:wasmimport env host_kv_get
func hostKvGet(keyPtr *byte, keyLen int32, outPtr *byte, outMaxLen int32) int32

//go:wasmimport env host_kv_set
func hostKvSet(keyPtr *byte, keyLen int32, valPtr *byte, valLen int32)

//go:wasmimport env host_http_callout
func hostHttpCallout(ptr *byte, length int32) int32

//go:wasmimport env host_http_callout_status
func hostHttpCalloutStatus(id int32) int32

//go:wasmimport env host_http_callout_body
func hostHttpCalloutBody(id int32, outPtr *byte, outMaxLen int32) int32

// ---------------------------------------------------------------------------
// WAF decisions
// ---------------------------------------------------------------------------

type Decision int32

const (
	DecisionAllow     Decision = 0
	DecisionBlock     Decision = 1
	DecisionChallenge Decision = 2
	DecisionLog       Decision = 3
)

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

// Log writes a message to the Sentinel log at INFO level.
func Log(msg string) {
	b := []byte(msg)
	if len(b) == 0 {
		return
	}
	hostLog(&b[0], int32(len(b)))
}

// ---------------------------------------------------------------------------
// Request inspection
// ---------------------------------------------------------------------------

// GetReqHeader looks up a request header by name (case-insensitive).
// Returns an empty string if the header is absent.
func GetReqHeader(name string) string {
	n := []byte(name)
	buf := make([]byte, 4096)
	written := hostGetReqHeader(&n[0], int32(len(n)), &buf[0], int32(len(buf)))
	if written <= 0 {
		return ""
	}
	return string(buf[:min(int(written), len(buf))])
}

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

// SetDecision sets the WAF decision for this request.
func SetDecision(d Decision) {
	hostSetDecision(int32(d))
}

// ---------------------------------------------------------------------------
// Anomaly scoring
// ---------------------------------------------------------------------------

// AddScore increments the anomaly score by delta (negative values are ignored).
func AddScore(delta uint32) {
	hostAddScore(int32(delta))
}

// ---------------------------------------------------------------------------
// Response headers
// ---------------------------------------------------------------------------

// SetResponseHeader queues a response header to be injected by the proxy.
func SetResponseHeader(name, value string) {
	n := []byte(name)
	v := []byte(value)
	hostSetHeader(&n[0], int32(len(n)), &v[0], int32(len(v)))
}

// ---------------------------------------------------------------------------
// Shared KV store
// ---------------------------------------------------------------------------

// KvGet reads a value from the shared plugin key-value store.
// Returns empty string if the key is absent.
func KvGet(key string) string {
	k := []byte(key)
	buf := make([]byte, 4096)
	written := hostKvGet(&k[0], int32(len(k)), &buf[0], int32(len(buf)))
	if written <= 0 {
		return ""
	}
	return string(buf[:min(int(written), len(buf))])
}

// KvSet stores a key-value pair in the shared plugin KV store.
func KvSet(key, value string) {
	k := []byte(key)
	v := []byte(value)
	hostKvSet(&k[0], int32(len(k)), &v[0], int32(len(v)))
}

// ---------------------------------------------------------------------------
// Outbound HTTP callout
// ---------------------------------------------------------------------------

// HttpCallout queues an outbound HTTP request and returns a callout ID.
// The request is specified as a JSON string with keys:
//
//	{"url": "...", "method": "GET", "headers": {"A": "B"}, "body": "..."}
//
// After evaluate() returns, the host executes the callout and calls
// evaluate() again so the plugin can read the result.
func HttpCallout(jsonReq string) int32 {
	b := []byte(jsonReq)
	if len(b) == 0 {
		return -1
	}
	return hostHttpCallout(&b[0], int32(len(b)))
}

// HttpCalloutStatus returns the HTTP status code of a completed callout,
// or 0 if the callout hasn't completed or failed.
func HttpCalloutStatus(id int32) int32 {
	return hostHttpCalloutStatus(id)
}

// HttpCalloutBody returns the response body of a completed callout,
// or empty string if the callout hasn't completed or the body is absent.
func HttpCalloutBody(id int32) string {
	buf := make([]byte, 65536)
	written := hostHttpCalloutBody(id, &buf[0], int32(len(buf)))
	if written <= 0 {
		return ""
	}
	return string(buf[:min(int(written), len(buf))])
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

// Contains reports whether substr is within s.
func Contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}