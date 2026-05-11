//! sentinel-rules — SRL rule DSL, compiler, and VM execution engine.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use sentinel_rules::RuleEngine;
//! use sentinel_core::context::{Phase, RequestContext};
//! use std::net::{IpAddr, Ipv4Addr};
//!
//! let engine = RuleEngine::from_srl(r#"
//! rule 942100 {
//!     phase    : request_body
//!     targets  : ARGS
//!     operator : rx /(?i)(select|union)\s/
//!     score    : +5
//!     action   : score
//!     message  : "SQLi"
//! }
//! "#).unwrap();
//!
//! let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
//! engine.evaluate(&mut ctx, Phase::RequestBody);
//! ```

pub mod compiler;
pub mod crs_compat;
pub mod dsl;
pub mod patterns;

use std::sync::Arc;

use anyhow::Result;
use sentinel_core::context::{Phase, RequestContext, WafDecision};

use compiler::emitter::CompiledRuleSet;
use compiler::{analysis, compile as do_compile};
use dsl::{ParseError, RuleFile};

// ---------------------------------------------------------------------------
// Public re-exports
// ---------------------------------------------------------------------------

pub use compiler::emitter::{Instruction, RuleMeta, TargetSpec};
pub use crs_compat::{import_secrule_conf, import_secrule_conf_dir};
pub use dsl::{ast, parse_rule_file};

// ---------------------------------------------------------------------------
// RuleEngine
// ---------------------------------------------------------------------------

/// The Sentinel rule engine.
///
/// Wraps a compiled `CompiledRuleSet` behind an `Arc` so it can be shared
/// across Tokio tasks and swapped atomically on hot-reload.
#[derive(Clone)]
pub struct RuleEngine {
    ruleset: Arc<CompiledRuleSet>,
}

impl std::fmt::Debug for RuleEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RuleEngine({:?})", self.ruleset)
    }
}

impl RuleEngine {
    /// Create a `RuleEngine` from an already-compiled `CompiledRuleSet`.
    pub fn new(ruleset: CompiledRuleSet) -> Self {
        Self {
            ruleset: Arc::new(ruleset),
        }
    }

    /// Parse and compile an SRL source string into a `RuleEngine`.
    pub fn from_srl(source: &str) -> Result<Self> {
        let file = parse_rule_file(source)?;
        let ruleset = compile(file)?;
        Ok(Self::new(ruleset))
    }

    /// Import a ModSecurity `.conf` source and compile into a `RuleEngine`.
    pub fn from_crs_conf(source: &str) -> Result<Self> {
        let file = import_secrule_conf(source)?;
        let ruleset = compile(file)?;
        Ok(Self::new(ruleset))
    }

    /// Run all rules for the given `phase` against `ctx`.
    ///
    /// Updates `ctx.decision`, `ctx.anomaly_score`, and `ctx.rule_matches`
    /// as rules fire.  Returns the current decision after this phase.
    pub fn evaluate(&self, ctx: &mut RequestContext, phase: Phase) -> WafDecision {
        compiler::vm::evaluate(&self.ruleset, ctx, phase)
    }

    /// Return the number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.ruleset.rule_meta.len()
    }
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

/// Parse an SRL source string into a `RuleFile` AST.
pub fn parse_srl(source: &str) -> Result<RuleFile, ParseError> {
    parse_rule_file(source)
}

/// Analyse + compile a `RuleFile` AST into a `CompiledRuleSet`.
pub fn compile(mut file: RuleFile) -> Result<CompiledRuleSet> {
    analysis::analyse(&mut file)?;
    do_compile(file)
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use bytes::Bytes;
    use sentinel_core::context::{Phase, RequestContext, WafDecision};

    use super::*;

    fn make_ctx() -> RequestContext {
        RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345)
    }

    // ------------------------------------------------------------------
    // SRL syntax tests
    // ------------------------------------------------------------------

    #[test]
    fn sqli_score_rule_fires() {
        let engine = RuleEngine::from_srl(
            r#"
rule 942100 {
    phase    : request_body
    targets  : ARGS
    operator : rx /(?i)(select|union|insert|update|delete|drop|exec)\s/
    score    : +5
    severity : critical
    message  : "SQL injection attempt"
    action   : score
}
"#,
        )
        .unwrap();

        let mut ctx = make_ctx();
        ctx.uri = "http://example.com/?id=1%20SELECT%20*%20FROM%20users%20WHERE%201=1"
            .parse()
            .unwrap();
        ctx.request_body = Some(Bytes::from("id=1 SELECT * FROM users"));

        engine.evaluate(&mut ctx, Phase::RequestBody);

        assert!(ctx.anomaly_score > 0, "anomaly_score should be > 0");
        assert_eq!(ctx.rule_matches.len(), 1, "one rule match expected");
        assert_eq!(ctx.rule_matches[0].rule_id, "942100");
    }

    #[test]
    fn block_rule_fires_and_sets_decision() {
        let engine = RuleEngine::from_srl(
            r#"
rule 942101 {
    phase    : request_body
    targets  : ARGS
    operator : contains_word ["xp_cmdshell", "exec("]
    score    : +8
    action   : block
    message  : "SQL stored procedure injection"
}
"#,
        )
        .unwrap();

        let mut ctx = make_ctx();
        ctx.uri = "http://example.com/?cmd=xp_cmdshell".parse().unwrap();

        engine.evaluate(&mut ctx, Phase::RequestBody);

        assert_eq!(ctx.decision, WafDecision::Block);
    }

    #[test]
    fn rule_does_not_fire_on_clean_request() {
        let engine = RuleEngine::from_srl(
            r#"
rule 942100 {
    phase    : request_body
    targets  : ARGS
    operator : rx /(?i)(select|union)\s/
    score    : +5
    action   : score
    message  : "SQLi"
}
"#,
        )
        .unwrap();

        let mut ctx = make_ctx();
        ctx.uri = "http://example.com/?name=John".parse().unwrap();

        engine.evaluate(&mut ctx, Phase::RequestBody);

        assert_eq!(ctx.anomaly_score, 0);
        assert_eq!(ctx.rule_matches.len(), 0);
    }

    #[test]
    fn anomaly_threshold_rule() {
        let engine = RuleEngine::from_srl(
            r#"
rule 942100 {
    phase    : request_body
    targets  : ARGS
    operator : rx /(?i)select\s/
    score    : +5
    action   : score
    message  : "SQLi"
}

rule 980130 {
    phase    : request_body
    operator : anomaly_score >= 5
    action   : block
    message  : "Anomaly score threshold exceeded"
}
"#,
        )
        .unwrap();

        let mut ctx = make_ctx();
        ctx.uri = "http://example.com/?q=select%20foo".parse().unwrap();

        engine.evaluate(&mut ctx, Phase::RequestBody);

        assert_eq!(ctx.decision, WafDecision::Block, "should block via anomaly threshold");
    }

    #[test]
    fn multi_target_or_rule() {
        let engine = RuleEngine::from_srl(
            r#"
rule 942200 {
    phase    : request_body
    targets  : ARGS | REQUEST_BODY
    operator : rx /(?i)xp_cmdshell/
    action   : block
    message  : "SQL xp_cmdshell"
}
"#,
        )
        .unwrap();

        // Match in REQUEST_BODY
        let mut ctx = make_ctx();
        ctx.uri = "http://example.com/".parse().unwrap();
        ctx.request_body = Some(Bytes::from("data=xp_cmdshell"));

        engine.evaluate(&mut ctx, Phase::RequestBody);

        assert_eq!(ctx.decision, WafDecision::Block);
    }

    // ------------------------------------------------------------------
    // CRS import tests
    // ------------------------------------------------------------------

    #[test]
    fn crs_import_fires_on_sqli() {
        let engine = RuleEngine::from_crs_conf(
            r#"SecRule ARGS "@rx (?i)(select|union|insert|update|delete|drop|exec)\s" "id:942100,phase:2,block,msg:'SQL Injection Attack',severity:'CRITICAL'""#,
        )
        .unwrap();

        let mut ctx = make_ctx();
        ctx.uri = "http://example.com/?id=1%20SELECT%20%2A".parse().unwrap();
        ctx.request_body = Some(Bytes::from("field=SELECT * FROM users"));

        engine.evaluate(&mut ctx, Phase::RequestBody);

        assert_eq!(ctx.decision, WafDecision::Block);
    }

    #[test]
    fn engine_rule_count() {
        let engine = RuleEngine::from_srl(
            r#"
rule 1 { phase: request_body targets: ARGS operator: exists action: log message: "a" }
rule 2 { phase: request_headers targets: ARGS operator: exists action: log message: "b" }
"#,
        )
        .unwrap();
        assert_eq!(engine.rule_count(), 2);
    }
}
