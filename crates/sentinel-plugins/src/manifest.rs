//! Plugin manifest — parses `sentinel-plugin.toml` metadata files.
//!
//! A manifest describes a plugin's identity, hooks, and permissions.
//! The runtime uses this to validate plugins at load time and to route
//! them to the correct WAF phases.

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Manifest structure
// ---------------------------------------------------------------------------

/// Top-level manifest parsed from a `sentinel-plugin.toml` file.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginManifest {
    pub plugin: PluginMeta,
}

/// Plugin identity and configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginMeta {
    /// Unique plugin name (e.g. `"my-jwt-validator"`).
    pub name: String,
    /// Semantic version string.
    pub version: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Author or organisation name.
    #[serde(default)]
    pub author: String,
    /// Path to the `.wasm` binary, relative to the manifest file.
    /// Defaults to `"plugin.wasm"`.
    #[serde(default = "default_wasm_path")]
    pub wasm: String,
    /// WAF phases the plugin hooks into.
    #[serde(default)]
    pub hooks: PluginHooks,
    /// ABI permissions the plugin requires.
    #[serde(default)]
    pub permissions: PluginPermissions,
}

fn default_wasm_path() -> String {
    "plugin.wasm".to_string()
}

/// Phases the plugin registers for.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PluginHooks {
    /// Run during Phase 1 (Request Headers).
    #[serde(default)]
    pub request_headers: bool,
    /// Run during Phase 2 (Request Body).
    #[serde(default)]
    pub request_body: bool,
    /// Run during Phase 4 (Response Headers).
    #[serde(default)]
    pub response_headers: bool,
    /// Run during Phase 5 (Response Body).
    #[serde(default)]
    pub response_body: bool,
}

/// ABI permissions — which host functions the plugin may call.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PluginPermissions {
    /// May write to the Sentinel log.
    #[serde(default)]
    pub host_log: bool,
    /// May read request headers.
    #[serde(default)]
    pub host_get_req_header: bool,
    /// May set the WAF decision.
    #[serde(default)]
    pub host_set_decision: bool,
    /// May increment the anomaly score.
    #[serde(default)]
    pub host_add_score: bool,
    /// May queue response headers.
    #[serde(default)]
    pub host_set_header: bool,
    /// May read from the shared KV store.
    #[serde(default)]
    pub host_kv_get: bool,
    /// May write to the shared KV store.
    #[serde(default)]
    pub host_kv_set: bool,
    /// May make outbound HTTP calls (future).
    #[serde(default)]
    pub host_http_callout: bool,
}

// ---------------------------------------------------------------------------
// Parse helpers
// ---------------------------------------------------------------------------

impl PluginManifest {
    /// Parse a manifest from raw TOML bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self, anyhow::Error> {
        let s = std::str::from_utf8(data)
            .map_err(|e| anyhow::anyhow!("manifest is not valid UTF-8: {e}"))?;
        Ok(toml::from_str(s)?)
    }

    /// Parse a manifest from a string.
    #[allow(clippy::should_implement_trait)] // intentional inherent method, not std::str::FromStr
    pub fn from_str(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_manifest() {
        let toml = r#"
[plugin]
name = "hello-world"
version = "0.1.0"
"#;
        let m = PluginManifest::from_str(toml).expect("parse");
        assert_eq!(m.plugin.name, "hello-world");
        assert_eq!(m.plugin.version, "0.1.0");
        assert_eq!(m.plugin.wasm, "plugin.wasm"); // default
        assert!(!m.plugin.hooks.request_headers);
        assert!(!m.plugin.permissions.host_set_decision);
    }

    #[test]
    fn parse_full_manifest() {
        let toml = r#"
[plugin]
name = "jwt-validator"
version = "1.2.3"
description = "Validates JWT tokens in Authorization header"
author = "Sentinel Labs"
wasm = "jwt_validator.wasm"

[plugin.hooks]
request_headers = true
request_body = false
response_headers = false
response_body = false

[plugin.permissions]
host_log = true
host_get_req_header = true
host_set_decision = true
host_add_score = true
host_set_header = false
host_kv_get = false
host_kv_set = false
host_http_callout = false
"#;
        let m = PluginManifest::from_str(toml).expect("parse");
        assert_eq!(m.plugin.name, "jwt-validator");
        assert_eq!(m.plugin.author, "Sentinel Labs");
        assert_eq!(m.plugin.wasm, "jwt_validator.wasm");
        assert!(m.plugin.hooks.request_headers);
        assert!(!m.plugin.hooks.request_body);
        assert!(m.plugin.permissions.host_set_decision);
        assert!(!m.plugin.permissions.host_kv_get);
    }

    #[test]
    fn defaults_all_false() {
        let toml = r#"
[plugin]
name = "minimal"
version = "0.1.0"
"#;
        let m = PluginManifest::from_str(toml).expect("parse");
        assert!(!m.plugin.hooks.request_headers);
        assert!(!m.plugin.hooks.request_body);
        assert!(!m.plugin.hooks.response_headers);
        assert!(!m.plugin.hooks.response_body);
        assert!(!m.plugin.permissions.host_log);
        assert!(!m.plugin.permissions.host_set_decision);
    }
}
