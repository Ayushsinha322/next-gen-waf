//! `srl-validate` — validate and dry-run an SRL rule using the REAL engine.
//!
//! WHY THIS EXISTS AS A SEPARATE BINARY.
//!
//! The rule DSL is parsed and compiled in Rust. The control plane is Go. Until
//! now the control plane "validated" rules with a string scanner that hunted for
//! `rx('...')`, pulled out the pattern and compiled it as a Go regex — ignoring
//! targets, phase and action, and accepting a syntax the real parser rejects.
//! That is worse than no validation: it told operators their rule was fine while
//! teaching them a DSL that could never run.
//!
//! There are three ways to fix that and only one of them is safe:
//!
//!   1. Reimplement the SRL parser in Go. Rejected. Two parsers for one language
//!      drift, and the divergence shows up as a rule that validates and then
//!      does not run — exactly the failure being fixed, reintroduced with more
//!      code.
//!   2. Have the control plane call a data-plane node over the network. Rejected
//!      for the availability coupling: you could not edit a rule while the data
//!      plane was rolling, which is precisely when you might need to.
//!   3. Bundle the real engine as a binary the control plane executes. Chosen.
//!      One compiler, synchronous, no network, and the answer comes from the same
//!      code that will run the rule in production.
//!
//! PROTOCOL: one JSON object on stdin, one on stdout, exit 0 whether or not the
//! rule is valid — a non-zero exit is reserved for the validator itself failing,
//! so the caller can tell "your rule is broken" from "validation did not run".
//!
//! Request:
//!   {"dsl": "...", "payload": "q=1' OR 1=1", "path": "/x", "method": "POST"}
//!
//! Response:
//!   {"valid": true, "rules": [{"id": 9999900, "phase": "request_body",
//!                              "action": "block", "severity": "critical"}],
//!    "matched": true, "score": 5, "decision": "Block",
//!    "matched_rule_ids": ["9999900"]}
//!   {"valid": false, "error": "syntax error at line 3, col 5: ..."}

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};

use sentinel_core::context::{Phase, RequestContext};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Default)]
struct Request {
    dsl: String,
    /// Optional sample input, treated as the query string and body so a rule
    /// targeting ARGS or REQUEST_BODY sees it either way.
    #[serde(default)]
    payload: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    method: String,
}

#[derive(Serialize)]
struct RuleSummary {
    id: u32,
    phase: String,
    action: String,
    severity: String,
}

#[derive(Serialize, Default)]
struct Response {
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// What the DSL actually compiled to. Surfacing this catches the case where a
    /// rule parses but defines nothing, which is not an error and is also not a
    /// working rule.
    rules: Vec<RuleSummary>,
    /// Dry-run results, present only when a payload was supplied.
    #[serde(skip_serializing_if = "Option::is_none")]
    matched: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    matched_rule_ids: Vec<String>,
}

fn emit(r: &Response) -> ! {
    match serde_json::to_string(r) {
        Ok(s) => println!("{s}"),
        // Cannot serialise the answer: say so on stderr and fail, rather than
        // printing something the caller might read as a verdict.
        Err(e) => {
            eprintln!("srl-validate: cannot serialise response: {e}");
            std::process::exit(2);
        }
    }
    std::process::exit(0);
}

fn main() {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("srl-validate: cannot read stdin: {e}");
        std::process::exit(2);
    }
    let req: Request = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("srl-validate: malformed request json: {e}");
            std::process::exit(2);
        }
    };

    if req.dsl.trim().is_empty() {
        emit(&Response {
            valid: false,
            error: Some("the rule is empty".to_string()),
            ..Default::default()
        });
    }

    // Parse + compile through the same path the data plane uses.
    let engine = match sentinel_rules::RuleEngine::from_srl(&req.dsl) {
        Ok(e) => e,
        Err(e) => emit(&Response {
            valid: false,
            error: Some(format!("{e}")),
            ..Default::default()
        }),
    };

    let summaries = summarise(&req.dsl);

    // A DSL that compiles to nothing is reported as invalid: it would be stored,
    // enabled, and enforce nothing, which is the confident-but-wrong state this
    // whole change exists to eliminate.
    if engine.rule_count() == 0 {
        emit(&Response {
            valid: false,
            error: Some(
                "parsed successfully but defined no rules — check the rule block is complete"
                    .to_string(),
            ),
            rules: summaries,
            ..Default::default()
        });
    }

    let mut resp = Response {
        valid: true,
        error: None,
        rules: summaries,
        ..Default::default()
    };

    if !req.payload.is_empty() {
        let (decision, score, ids) = dry_run(&engine, &req);
        resp.matched = Some(!ids.is_empty());
        resp.decision = Some(decision);
        resp.score = Some(score);
        resp.matched_rule_ids = ids;
    }

    emit(&resp);
}

/// CamelCase -> snake_case, so a phase reads `request_body` and not `requestbody`.
fn snake(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.extend(c.to_lowercase());
    }
    out
}

/// Describe the compiled rules by re-parsing the AST. Uses the AST rather than
/// the compiled form because the AST still carries the operator-facing fields
/// (phase, action, severity) in the shape an operator wrote them.
fn summarise(dsl: &str) -> Vec<RuleSummary> {
    let Ok(file) = sentinel_rules::parse_srl(dsl) else {
        return Vec::new();
    };
    file.items
        .iter()
        .filter_map(|item| match item {
            sentinel_rules::ast::RuleItem::Rule(r) => Some(RuleSummary {
                id: r.id,
                phase: snake(&format!("{:?}", r.phase)),
                action: snake(&format!("{:?}", r.action)),
                // severity is Option<_>; Debug on the Option renders "Some(High)"
                // which is not something to show an operator.
                severity: r
                    .severity
                    .as_ref()
                    .map(|s| snake(&format!("{s:?}")))
                    .unwrap_or_else(|| "unset".to_string()),
            }),
            _ => None,
        })
        .collect()
}

/// Evaluate the rule against a synthetic request.
///
/// The payload is offered as BOTH the query string and the request body, because
/// an operator testing `targets: ARGS` and one testing `targets: REQUEST_BODY`
/// both reasonably expect their sample to be seen. Every phase is run in order so
/// a rule declared in any phase gets its chance; the threshold is 0 to disable
/// early exit, so the result reflects this rule alone rather than an accumulated
/// score cutting evaluation short.
fn dry_run(engine: &sentinel_rules::RuleEngine, req: &Request) -> (String, u32, Vec<String>) {
    let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);

    let path = if req.path.is_empty() { "/" } else { &req.path };
    let uri = format!("{path}?{}", req.payload);
    if let Ok(u) = uri.parse::<http::Uri>() {
        ctx.uri = u;
    }
    if !req.method.is_empty() {
        if let Ok(m) = req.method.parse::<http::Method>() {
            ctx.method = m;
        }
    }
    ctx.request_body = Some(req.payload.clone().into_bytes().into());

    let mut decision = sentinel_core::context::WafDecision::Allow;
    for phase in [
        Phase::RequestHeaders,
        Phase::RequestBody,
        Phase::ResponseHeaders,
        Phase::ResponseBody,
    ] {
        ctx.phase = phase.clone();
        let d = engine.evaluate(&mut ctx, phase, 0);
        if d != sentinel_core::context::WafDecision::Allow {
            decision = d;
        }
    }

    let ids = ctx
        .rule_matches
        .iter()
        .map(|m| m.rule_id.clone())
        .collect::<Vec<_>>();
    (format!("{decision:?}"), ctx.anomaly_score, ids)
}
