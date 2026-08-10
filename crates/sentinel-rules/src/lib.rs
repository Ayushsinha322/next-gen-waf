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
//! engine.evaluate(&mut ctx, Phase::RequestBody, 0);
//! ```

pub mod compiler;
pub mod crs_compat;
pub mod dsl;
pub mod ssrf;

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
    ///
    /// `anomaly_threshold` enables early-exit: when a rule pushes the anomaly
    /// score at or above this value the VM stops evaluating remaining rules
    /// and returns `WafDecision::Block`.  Pass 0 to disable.
    pub fn evaluate(
        &self,
        ctx: &mut RequestContext,
        phase: Phase,
        anomaly_threshold: u32,
    ) -> WafDecision {
        compiler::vm::evaluate(&self.ruleset, ctx, phase, anomaly_threshold)
    }

    /// Return the number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.ruleset.rule_meta.len()
    }

    /// `true` if this rule set has any rules in the response-body phase.
    ///
    /// The proxy uses this to decide whether to buffer the response body for
    /// inspection — most rule sets (e.g. CRS REQUEST-* only) have none, so the
    /// response can stream straight through with zero added latency.
    ///
    /// Checks rule metadata rather than the phase program, because `SecMarker`
    /// directives are emitted into every phase program (so a non-empty program
    /// does not by itself imply a real response-body rule).
    pub fn has_response_body_rules(&self) -> bool {
        use crate::dsl::ast::RulePhase;
        self.ruleset
            .rule_meta
            .values()
            .any(|m| m.phase == RulePhase::ResponseBody)
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

        engine.evaluate(&mut ctx, Phase::RequestBody, 0);

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

        engine.evaluate(&mut ctx, Phase::RequestBody, 0);

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

        engine.evaluate(&mut ctx, Phase::RequestBody, 0);

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

        engine.evaluate(&mut ctx, Phase::RequestBody, 0);

        assert_eq!(
            ctx.decision,
            WafDecision::Block,
            "should block via anomaly threshold"
        );
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

        engine.evaluate(&mut ctx, Phase::RequestBody, 0);

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

        engine.evaluate(&mut ctx, Phase::RequestBody, 0);

        assert_eq!(ctx.decision, WafDecision::Block);
    }

    // ------------------------------------------------------------------
    // TX-variable state engine: category-score / correlation rules
    // ------------------------------------------------------------------

    /// A detection rule writes a category score into the TX store via `setvar`;
    /// a later correlation rule reads it back with `TX:` and blocks. This is the
    /// end-to-end proof that arbitrary `tx.*` state now flows between rules
    /// (previously every non-anomaly-score setvar was dropped, so this was inert).
    #[test]
    fn crs_category_score_correlation_rule_fires() {
        let engine = RuleEngine::from_crs_conf(
            "SecRule ARGS \"@rx (?i)select\" \"id:9001,phase:2,pass,setvar:tx.sql_injection_score=+5\"\n\
             SecRule TX:SQL_INJECTION_SCORE \"@ge 5\" \"id:9002,phase:2,block,msg:'Inbound SQLi category correlation'\"",
        )
        .unwrap();

        let mut ctx = make_ctx();
        ctx.uri = "http://example.com/?q=select".parse().unwrap();

        engine.evaluate(&mut ctx, Phase::RequestBody, 0);

        assert_eq!(
            ctx.tx_vars.get("SQL_INJECTION_SCORE").map(String::as_str),
            Some("5"),
            "detection rule must accumulate the category score in the TX store"
        );
        assert_eq!(
            ctx.decision,
            WafDecision::Block,
            "correlation rule should block after reading TX:SQL_INJECTION_SCORE"
        );
    }

    /// The correlation rule must NOT fire when the category score never crossed
    /// the threshold — proving the block is driven by real TX state, not a
    /// spurious match on an absent variable.
    #[test]
    fn crs_correlation_does_not_fire_below_threshold() {
        let engine = RuleEngine::from_crs_conf(
            "SecRule ARGS \"@rx (?i)select\" \"id:9001,phase:2,pass,setvar:tx.sql_injection_score=+5\"\n\
             SecRule TX:SQL_INJECTION_SCORE \"@ge 5\" \"id:9002,phase:2,block,msg:'Inbound SQLi category correlation'\"",
        )
        .unwrap();

        let mut ctx = make_ctx();
        // Clean request — the detection rule never matches, so the category
        // score stays unset (0) and the correlation rule stays silent.
        ctx.uri = "http://example.com/?q=hello".parse().unwrap();

        engine.evaluate(&mut ctx, Phase::RequestBody, 0);

        assert!(!ctx.tx_vars.contains_key("SQL_INJECTION_SCORE"));
        assert_ne!(ctx.decision, WafDecision::Block);
    }

    /// `setvar` values may reference other TX variables / CRS constants via
    /// `%{...}`; the macro is expanded at fire time. Here the category score is
    /// incremented by `%{tx.critical_anomaly_score}` (CRS constant = 5).
    #[test]
    fn crs_setvar_macro_expands_crs_constant() {
        let engine = RuleEngine::from_crs_conf(
            "SecRule ARGS \"@rx (?i)select\" \"id:9101,phase:2,pass,setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}\"\n\
             SecRule TX:SQL_INJECTION_SCORE \"@ge 5\" \"id:9102,phase:2,block,msg:'correlation via macro'\"",
        )
        .unwrap();

        let mut ctx = make_ctx();
        ctx.uri = "http://example.com/?q=select".parse().unwrap();

        engine.evaluate(&mut ctx, Phase::RequestBody, 0);

        assert_eq!(
            ctx.tx_vars.get("SQL_INJECTION_SCORE").map(String::as_str),
            Some("5"),
            "%{{tx.critical_anomaly_score}} must expand to the CRS constant 5"
        );
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

    // ------------------------------------------------------------------
    // Transform tests
    // ------------------------------------------------------------------

    #[test]
    fn transform_lowercase_catches_uppercase_attack() {
        // Rule uses @rx with a lowercase pattern; t:lowercase ensures it matches UPPERCASE input.
        let engine = RuleEngine::from_crs_conf(
            r#"SecRule ARGS "@rx select" "id:1001,phase:2,block,t:lowercase,msg:'SQLi lower'""#,
        )
        .unwrap();

        let mut ctx = make_ctx();
        ctx.uri = "http://example.com/?q=SELECT%201".parse().unwrap();

        engine.evaluate(&mut ctx, Phase::RequestBody, 0);
        assert_eq!(
            ctx.decision,
            WafDecision::Block,
            "lowercase transform should normalise SELECT → select"
        );
    }

    #[test]
    fn transform_lowercase_clean_request_passes() {
        let engine = RuleEngine::from_crs_conf(
            r#"SecRule ARGS "@rx select" "id:1001,phase:2,block,t:lowercase,msg:'SQLi lower'""#,
        )
        .unwrap();

        let mut ctx = make_ctx();
        ctx.uri = "http://example.com/?q=normal+query".parse().unwrap();

        engine.evaluate(&mut ctx, Phase::RequestBody, 0);
        assert!(
            ctx.decision != WafDecision::Block,
            "clean request must not be blocked by lowercase rule"
        );
    }

    #[test]
    fn transform_remove_nulls_strips_before_match() {
        // Null-byte injection: "se\0lect" evades naive regex but RemoveNulls fixes that.
        let engine = RuleEngine::from_crs_conf(
            r#"SecRule ARGS "@rx select" "id:1002,phase:2,block,t:removeNulls,t:lowercase,msg:'null inject'""#,
        )
        .unwrap();

        let mut ctx = make_ctx();
        // "se\x00lect" — null byte injected into the keyword
        ctx.uri = "http://example.com/?x=se%00lect".parse().unwrap();

        engine.evaluate(&mut ctx, Phase::RequestBody, 0);
        assert_eq!(
            ctx.decision,
            WafDecision::Block,
            "removeNulls + lowercase should expose the injected keyword"
        );
    }

    #[test]
    fn transform_html_entity_decode_catches_encoded_xss() {
        // &lt;script&gt; decoded → <script> which the regex matches.
        let engine = RuleEngine::from_crs_conf(
            r#"SecRule ARGS "@rx <script" "id:1003,phase:2,block,t:htmlEntityDecode,t:lowercase,msg:'XSS'""#,
        )
        .unwrap();

        let mut ctx = make_ctx();
        ctx.uri = "http://example.com/?x=%26lt%3Bscript%26gt%3B"
            .parse()
            .unwrap();
        // Decoded ARGS value: "&lt;script&gt;" — htmlEntityDecode turns this to "<script>"
        ctx.request_body = Some(Bytes::from("x=&lt;script&gt;alert(1)&lt;/script&gt;"));

        engine.evaluate(&mut ctx, Phase::RequestBody, 0);
        assert_eq!(
            ctx.decision,
            WafDecision::Block,
            "htmlEntityDecode should expose encoded script tag"
        );
    }

    // ------------------------------------------------------------------
    // setvar fix tests
    // ------------------------------------------------------------------

    #[test]
    fn setvar_only_anomaly_score_lhs_counts() {
        use crate::crs_compat::secrule::parse_crs_actions;
        // LHS is a category tracker — should NOT contribute to rule score_delta
        let actions = parse_crs_actions(
            "id:1,phase:2,pass,setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}",
        );
        assert_eq!(
            actions.score_delta, None,
            "category score vars must not be counted as anomaly_score deltas"
        );
    }

    #[test]
    fn setvar_anomaly_score_lhs_gives_delta() {
        use crate::crs_compat::secrule::parse_crs_actions;
        let actions = parse_crs_actions(
            "id:1,phase:2,pass,setvar:tx.anomaly_score=+%{tx.critical_anomaly_score}",
        );
        assert_eq!(actions.score_delta, Some(5));
    }

    #[test]
    fn setvar_negative_delta() {
        use crate::crs_compat::secrule::parse_crs_actions;
        let actions = parse_crs_actions("id:1,phase:2,pass,setvar:tx.anomaly_score=-3");
        assert_eq!(actions.score_delta, Some(-3));
    }

    #[test]
    fn setvar_absolute_assignment_ignored() {
        use crate::crs_compat::secrule::parse_crs_actions;
        // No + or - prefix → absolute assignment, not a delta
        let actions = parse_crs_actions("id:1,phase:2,pass,setvar:tx.anomaly_score=10");
        assert_eq!(
            actions.score_delta, None,
            "absolute setvar assignment must not be treated as a delta"
        );
    }

    // ------------------------------------------------------------------
    // skipAfter tests
    // ------------------------------------------------------------------

    #[test]
    fn skipafter_is_not_in_unknown_actions() {
        use crate::crs_compat::secrule::parse_crs_actions;
        let actions = parse_crs_actions(
            "id:920020,phase:1,pass,nolog,skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT",
        );
        assert!(
            actions.unknown.is_empty(),
            "skipAfter must not produce unrecognised-action warnings, got: {:?}",
            actions.unknown
        );
        assert_eq!(
            actions.skip_after.as_deref(),
            Some("END-REQUEST-920-PROTOCOL-ENFORCEMENT")
        );
    }

    #[test]
    fn skipafter_stored_on_rule_def() {
        use crate::crs_compat::import_secrule_conf;
        use crate::dsl::ast::RuleItem;
        let src = r#"SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" "id:920020,phase:1,pass,nolog,skipAfter:END-REQUEST-ENFORCEMENT""#;
        let rf = import_secrule_conf(src).expect("import");
        let rule = rf
            .items
            .iter()
            .find_map(|i| {
                if let RuleItem::Rule(r) = i {
                    Some(r)
                } else {
                    None
                }
            })
            .expect("rule");
        assert_eq!(rule.skip_after.as_deref(), Some("END-REQUEST-ENFORCEMENT"));
    }

    #[test]
    fn skipafter_enforced_in_vm() {
        // Gate rule (id=10): fires for ARGS="safe" → skipAfter:SECTION_END skips rule 20.
        // Block rule (id=20): fires for any ARGS — must be skipped when gate fires.
        // SecMarker SECTION_END
        //
        // This matches real CRS paranoia-level gating: the gate rule fires when
        // the input meets a "safe" criterion and jumps past the stricter rules.
        let src = r#"
SecRule ARGS "@rx ^safe$" "id:10,phase:2,pass,nolog,skipAfter:SECTION_END,msg:'gate fired'"
SecRule ARGS "@rx ." "id:20,phase:2,block,msg:'catch-all block — skipped when gate fires'"
SecMarker "SECTION_END"
"#;
        use crate::crs_compat::import_secrule_conf;
        let rf = import_secrule_conf(src).expect("import");
        let engine = RuleEngine::new(compile(rf).expect("compile"));

        // === Path 1: ARGS="safe" → gate fires, block rule must be skipped ===
        let mut ctx_gate = make_ctx();
        ctx_gate.uri = "http://example.com/?param=safe".parse().unwrap();
        engine.evaluate(&mut ctx_gate, Phase::RequestBody, 0);

        assert!(
            ctx_gate.rule_matches.iter().any(|m| m.rule_id == "10"),
            "gate rule must fire for ARGS=safe"
        );
        assert!(
            !ctx_gate.rule_matches.iter().any(|m| m.rule_id == "20"),
            "block rule must be skipped when gate fires"
        );
        assert_eq!(
            ctx_gate.decision,
            WafDecision::Allow,
            "gate uses pass — must stay Allow"
        );

        // === Path 2: ARGS="other" → gate does NOT fire, block rule runs ===
        let mut ctx_no_gate = make_ctx();
        ctx_no_gate.uri = "http://example.com/?param=other".parse().unwrap();
        engine.evaluate(&mut ctx_no_gate, Phase::RequestBody, 0);

        assert!(
            !ctx_no_gate.rule_matches.iter().any(|m| m.rule_id == "10"),
            "gate must not fire for ARGS=other"
        );
        assert!(
            ctx_no_gate.rule_matches.iter().any(|m| m.rule_id == "20"),
            "block rule must fire when gate doesn't"
        );
        assert_eq!(ctx_no_gate.decision, WafDecision::Block);
    }
}
