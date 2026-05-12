//! sentinel-plugins — WASM plugin host runtime for Sentinel WAF.
//!
//! This crate provides:
//!   - [`PluginRuntime`] — loads `.wasm` modules and evaluates them against
//!     incoming requests.
//!   - A [Host ABI](abi) that guest plugins import (`host_log`,
//!     `host_get_req_header`, `host_set_decision`).
//!
//! # Quick start
//!
//! ```ignore
//! use sentinel_plugins::PluginRuntime;
//!
//! let mut rt = PluginRuntime::new().unwrap();
//! rt.load_plugin("hello", &std::fs::read("hello.wasm").unwrap()).unwrap();
//!
//! let decision = rt.evaluate_plugin("hello", &ctx).await;
//! ```

pub mod abi;
pub mod manifest;
pub mod runtime;

pub use abi::{HttpCalloutRequest, HttpCalloutResult};
pub use manifest::PluginManifest;
pub use runtime::{PluginEvalResult, PluginRuntime};
