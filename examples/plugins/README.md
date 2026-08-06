# Sentinel WAF plugins

A plugin is a WebAssembly module that runs inside the data plane on the phases it
asks for, and can read the request, influence the anomaly score, and set the WAF
decision. Plugins are uploaded as a `.zip` through the dashboard (or
`POST /api/v1/plugins`) and are distributed to every WAF node automatically.

## Archive layout

An uploadable archive contains a manifest and the module, either at the root or
inside a single top-level directory:

```
ua-guard.zip
├── sentinel-plugin.toml
└── plugin.wasm
```

`plugin.wasm` is the default; set `wasm = "..."` in the manifest to use another
path. See [`ua-guard/sentinel-plugin.toml`](ua-guard/sentinel-plugin.toml) for a
fully-commented manifest.

## Building

```bash
cd ua-guard
./build.sh          # installs the wasm32 target if needed, produces ua-guard.zip
```

Requirements: `[lib] crate-type = ["cdylib"]`, the `wasm32-unknown-unknown`
target, and an exported `evaluate()`.

Example plugin crates are deliberately **excluded from the workspace** (see the
root `Cargo.toml`): a workspace build would try to build them for the host
target, where their `env` host-function imports cannot resolve.

## The contract

Export one function; the host calls it once per request for each phase the
manifest enables:

```rust
#[no_mangle]
pub extern "C" fn evaluate() { /* ... */ }
```

Host functions are imported from the `env` module. The authoritative list is
[`crates/sentinel-plugins/src/sdk.rs`](../../crates/sentinel-plugins/src/sdk.rs),
with the host-side implementations in
[`abi.rs`](../../crates/sentinel-plugins/src/abi.rs). The common ones:

| Function | Purpose |
|---|---|
| `host_log(ptr, len)` | Write to the host's structured log |
| `host_get_header(name_ptr, name_len, out_ptr, out_cap) -> i32` | Read a request header; `-1` if absent |
| `host_get_decision() -> i32` / `host_set_decision(d)` | Read/override the verdict (0 Allow, 1 Block, 2 Challenge) |
| `host_add_score(delta)` | Contribute to the request's anomaly score |
| `host_set_header(...)` | Add or overwrite a response header |
| `host_kv_get` / `host_kv_set` | Shared key-value store across plugins |

## Lifecycle and safety

- An uploaded plugin is **inactive until enabled**. Loading a module that can set
  the WAF decision is as privileged as changing a rule, so it takes a second,
  explicit action; uploading alone never changes how traffic is judged.
- Re-uploading the same `name` is an **upgrade in place**, not a second copy.
- Nodes poll for the enabled set, download a module only when its `sha256` is new
  to them, and **verify the digest before compiling**.
- Enabling, disabling, deleting and installing are all written to the
  tamper-evident audit log, including the permissions the plugin declared.

**What the sandbox does guarantee:** wasmtime isolation, a fuel (instruction)
limit, epoch-based interruption and a per-plugin memory cap. A plugin cannot
escape its memory or hang the proxy.

**What it does not:** the `[plugin.permissions]` block is *declared intent only*.
The runtime does not currently gate host calls on it, so any loaded plugin can
call any host function the ABI exposes. Treat enabling a plugin as running
trusted code, and review the module's source. Only upload plugins you trust.

## Scoring vs blocking

Prefer `host_add_score` over `host_set_decision` unless the signal is
unambiguous. Scoring lets the site's threshold, the rule engine and the ML layer
weigh your signal with everything else; blocking overrides all of them. `ua-guard`
demonstrates both: it blocks an explicit scanner name and merely scores a generic
scripted client.
