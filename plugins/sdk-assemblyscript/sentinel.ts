/**
 * Sentinel WAF — AssemblyScript guest SDK for WASM plugins.
 *
 * Plugins must be compiled with `asc` (AssemblyScript compiler) targeting
 * `--target release` and importing the Sentinel host ABI.
 *
 * # Quick start
 *
 * ```ts
 * import { log, getReqHeader, setDecision, Decision } from "./sentinel";
 *
 * export function evaluate(): void {
 *   log("Hello from AssemblyScript plugin!");
 *   let ua = getReqHeader("user-agent");
 *   if (ua && ua.includes("sqlmap")) {
 *     setDecision(Decision.Block);
 *   }
 * }
 * ```
 *
 * Build: `asc plugin.ts -o plugin.wasm --optimize --target release`
 */

// ---------------------------------------------------------------------------
// Host ABI imports
// ---------------------------------------------------------------------------

@external("env", "host_log")
declare function host_log(ptr: usize, len: i32): void;

@external("env", "host_get_req_header")
declare function host_get_req_header(
  name_ptr: usize, name_len: i32,
  out_ptr: usize, out_max_len: i32
): i32;

@external("env", "host_set_decision")
declare function host_set_decision(code: i32): void;

@external("env", "host_add_score")
declare function host_add_score(delta: i32): void;

@external("env", "host_set_header")
declare function host_set_header(
  name_ptr: usize, name_len: i32,
  val_ptr: usize, val_len: i32
): void;

@external("env", "host_kv_get")
declare function host_kv_get(
  key_ptr: usize, key_len: i32,
  out_ptr: usize, out_max_len: i32
): i32;

@external("env", "host_kv_set")
declare function host_kv_set(
  key_ptr: usize, key_len: i32,
  val_ptr: usize, val_len: i32
): void;

@external("env", "host_http_callout")
declare function host_http_callout(ptr: usize, len: i32): i32;

@external("env", "host_http_callout_status")
declare function host_http_callout_status(id: i32): i32;

@external("env", "host_http_callout_body")
declare function host_http_callout_body(
  id: i32, out_ptr: usize, out_max_len: i32
): i32;

// ---------------------------------------------------------------------------
// WAF decisions
// ---------------------------------------------------------------------------

export enum Decision {
  Allow = 0,
  Block = 1,
  Challenge = 2,
  Log = 3,
}

// ---------------------------------------------------------------------------
// Memory helpers
// ---------------------------------------------------------------------------

// These override the default AssemblyScript allocator to use the host
// memory (AssemblyScript manages its own linear memory within WASM).

function stringToPtr(s: string): usize {
  if (s.length == 0) return changetype<usize>(0);
  let buf = String.UTF8.encode(s);
  return changetype<usize>(buf);
}

function ptrToString(ptr: usize, len: i32): string {
  if (ptr == 0 || len <= 0) return "";
  return String.UTF8.decodeUnsafe(ptr, len);
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

/** Write a message to the Sentinel log at INFO level. */
export function log(msg: string): void {
  let encoded = String.UTF8.encode(msg);
  host_log(changetype<usize>(encoded), encoded.byteLength as i32);
}

// ---------------------------------------------------------------------------
// Request inspection
// ---------------------------------------------------------------------------

/** Look up a request header by name (case-insensitive). Returns null if absent. */
export function getReqHeader(name: string): string | null {
  let encoded = String.UTF8.encode(name);
  let buf = new Array<u8>(4096);
  let bufPtr = changetype<usize>(buf.buffer) + buf.byteOffset;
  let written = host_get_req_header(
    changetype<usize>(encoded), encoded.byteLength as i32,
    bufPtr, 4096
  );
  if (written <= 0) return null;
  return ptrToString(bufPtr, written);
}

// ---------------------------------------------------------------------------
// Decision
// ---------------------------------------------------------------------------

/** Set the WAF decision for this request. */
export function setDecision(d: Decision): void {
  host_set_decision(d as i32);
}

// ---------------------------------------------------------------------------
// Anomaly scoring
// ---------------------------------------------------------------------------

/** Increment the anomaly score by delta (negative values are ignored). */
export function addScore(delta: u32): void {
  host_add_score(delta as i32);
}

// ---------------------------------------------------------------------------
// Response headers
// ---------------------------------------------------------------------------

/** Queue a response header to be injected by the proxy. */
export function setResponseHeader(name: string, value: string): void {
  let n = String.UTF8.encode(name);
  let v = String.UTF8.encode(value);
  host_set_header(
    changetype<usize>(n), n.byteLength as i32,
    changetype<usize>(v), v.byteLength as i32
  );
}

// ---------------------------------------------------------------------------
// Shared KV store
// ---------------------------------------------------------------------------

/** Read a value from the shared plugin KV store. Returns null if absent. */
export function kvGet(key: string): string | null {
  let k = String.UTF8.encode(key);
  let buf = new Array<u8>(4096);
  let bufPtr = changetype<usize>(buf.buffer) + buf.byteOffset;
  let written = host_kv_get(
    changetype<usize>(k), k.byteLength as i32,
    bufPtr, 4096
  );
  if (written <= 0) return null;
  return ptrToString(bufPtr, written);
}

/** Store a key-value pair in the shared plugin KV store. */
export function kvSet(key: string, value: string): void {
  let k = String.UTF8.encode(key);
  let v = String.UTF8.encode(value);
  host_kv_set(
    changetype<usize>(k), k.byteLength as i32,
    changetype<usize>(v), v.byteLength as i32
  );
}

// ---------------------------------------------------------------------------
// Outbound HTTP callout
// ---------------------------------------------------------------------------

/**
 * Queue an outbound HTTP request and return a callout ID.
 * The request is specified as a JSON string.
 * After evaluate() returns, the host executes the callout and calls
 * evaluate() again so the plugin can read the result.
 */
export function httpCallout(jsonReq: string): i32 {
  let encoded = String.UTF8.encode(jsonReq);
  return host_http_callout(
    changetype<usize>(encoded), encoded.byteLength as i32
  );
}

/** Return the HTTP status code of a completed callout, or 0 if pending/failed. */
export function httpCalloutStatus(id: i32): i32 {
  return host_http_callout_status(id);
}

/** Return the response body of a completed callout, or null if pending/failed. */
export function httpCalloutBody(id: i32): string | null {
  let buf = new Array<u8>(65536);
  let bufPtr = changetype<usize>(buf.buffer) + buf.byteOffset;
  let written = host_http_callout_body(id, bufPtr, 65536);
  if (written <= 0) return null;
  return ptrToString(bufPtr, written);
}