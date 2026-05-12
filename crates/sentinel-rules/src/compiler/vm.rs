use sentinel_core::context::{Phase, RequestContext, RuleMatch, Severity, WafDecision};
use tracing::{debug, warn};

use super::emitter::{CompiledRuleSet, Instruction, RuleMeta, TargetSpec};
use crate::dsl::ast::{RuleAction, RulePhase, RuleSeverity};

fn rule_phase_to_phase(rp: RulePhase) -> Phase {
    match rp {
        RulePhase::Connection => Phase::Connection,
        RulePhase::RequestHeaders => Phase::RequestHeaders,
        RulePhase::RequestBody => Phase::RequestBody,
        RulePhase::Upstream => Phase::Upstream,
        RulePhase::ResponseHeaders => Phase::ResponseHeaders,
        RulePhase::ResponseBody => Phase::ResponseBody,
        RulePhase::Logging => Phase::Logging,
    }
}

// ---------------------------------------------------------------------------
// Stack value
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum StackVal {
    Bool(bool),
    Strings(Vec<String>),
    Int(i64),
    Float(f32),
    Absent,
}

// ---------------------------------------------------------------------------
// Target extraction helpers
// ---------------------------------------------------------------------------

/// Parse a URL-encoded query string into (key, value) pairs.
fn parse_query_params(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let mut parts = kv.splitn(2, '=');
            let k = percent_decode(parts.next().unwrap_or(""));
            let v = percent_decode(parts.next().unwrap_or(""));
            (k, v)
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// Parse the Cookie header into (name, value) pairs.
fn parse_cookies(header_val: &str) -> Vec<(String, String)> {
    header_val
        .split(';')
        .map(|c| c.trim())
        .filter_map(|c| {
            let mut p = c.splitn(2, '=');
            Some((p.next()?.to_owned(), p.next().unwrap_or("").to_owned()))
        })
        .collect()
}

fn extract_target(spec: &TargetSpec, ctx: &RequestContext) -> Vec<String> {
    match spec {
        TargetSpec::Args => {
            parse_query_params(ctx.uri.query().unwrap_or(""))
                .into_iter()
                .map(|(_, v)| v)
                .collect()
        }
        TargetSpec::ArgsNames => {
            parse_query_params(ctx.uri.query().unwrap_or(""))
                .into_iter()
                .map(|(k, _)| k)
                .collect()
        }
        TargetSpec::RequestUri => vec![ctx.uri.to_string()],
        TargetSpec::RequestLine => vec![format!(
            "{} {} {:?}",
            ctx.method, ctx.uri, ctx.http_version
        )],
        TargetSpec::RequestBody => {
            ctx.request_body
                .as_ref()
                .map(|b| vec![String::from_utf8_lossy(b).into_owned()])
                .unwrap_or_default()
        }
        TargetSpec::RequestHeadersAll => ctx
            .request_headers
            .values()
            .filter_map(|v| v.to_str().ok())
            .map(String::from)
            .collect(),
        TargetSpec::RequestHeader(name) => ctx
            .request_headers
            .get(name.as_str())
            .and_then(|v| v.to_str().ok())
            .map(|v| vec![v.to_owned()])
            .unwrap_or_default(),
        TargetSpec::RequestCookiesAll => {
            if let Some(cookie_hdr) = ctx.request_headers.get("cookie") {
                if let Ok(s) = cookie_hdr.to_str() {
                    return parse_cookies(s).into_iter().map(|(_, v)| v).collect();
                }
            }
            vec![]
        }
        TargetSpec::RequestCookie(name) => {
            if let Some(cookie_hdr) = ctx.request_headers.get("cookie") {
                if let Ok(s) = cookie_hdr.to_str() {
                    return parse_cookies(s)
                        .into_iter()
                        .filter(|(k, _)| k == name)
                        .map(|(_, v)| v)
                        .collect();
                }
            }
            vec![]
        }
        TargetSpec::ResponseHeadersAll => ctx
            .response_headers
            .as_ref()
            .map(|h| {
                h.values()
                    .filter_map(|v| v.to_str().ok())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default(),
        TargetSpec::ResponseHeader(name) => ctx
            .response_headers
            .as_ref()
            .and_then(|h| h.get(name.as_str()))
            .and_then(|v| v.to_str().ok())
            .map(|v| vec![v.to_owned()])
            .unwrap_or_default(),
        TargetSpec::ResponseBody => vec![], // TODO: implement when Phase 5 wired
        TargetSpec::RemoteAddr => vec![ctx.client_ip.to_string()],
        TargetSpec::Geo => vec![], // TODO: GeoIP in Phase 2
        TargetSpec::TxVar(name) => ctx
            .tx_vars
            .get(name)
            .map(|v| vec![v.clone()])
            .unwrap_or_default(),
        TargetSpec::CountOf(inner) => {
            let count = match inner.as_ref() {
                TargetSpec::RequestHeader(name) => {
                    ctx.request_headers.get_all(name.as_str()).iter().count()
                }
                TargetSpec::ResponseHeader(name) => ctx
                    .response_headers
                    .as_ref()
                    .map(|h| h.get_all(name.as_str()).iter().count())
                    .unwrap_or(0),
                other => extract_target(other, ctx).len(),
            };
            vec![count.to_string()]
        }
    }
}

// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------

fn map_severity(s: RuleSeverity) -> Severity {
    match s {
        RuleSeverity::Critical => Severity::Critical,
        RuleSeverity::High => Severity::High,
        RuleSeverity::Medium => Severity::Medium,
        RuleSeverity::Low => Severity::Low,
        RuleSeverity::Notice => Severity::Notice,
    }
}

// ---------------------------------------------------------------------------
// VM evaluator
// ---------------------------------------------------------------------------

/// Execute the instruction program for `phase` against `ctx`.
///
/// Returns the final `WafDecision` (may update `ctx.decision` and
/// `ctx.rule_matches` internally).
pub fn evaluate(ruleset: &CompiledRuleSet, ctx: &mut RequestContext, phase: Phase) -> WafDecision {
    let phase_idx = phase as usize;
    let program = &ruleset.phase_programs[phase_idx];

    let mut stack: Vec<StackVal> = Vec::with_capacity(16);
    let mut ip: usize = 0; // instruction pointer

    while ip < program.len() {
        let instr = &program[ip];
        match instr {
            Instruction::LoadTarget(spec) => {
                let values = extract_target(spec, ctx);
                stack.push(StackVal::Strings(values));
            }

            Instruction::MatchRx { pattern_id } => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let regex = &ruleset.patterns[*pattern_id];
                    let matched = values.iter().any(|s| regex.is_match(s));
                    debug!(pattern = %regex.as_str(), matched, "MatchRx");
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::MatchMulti { set_id } => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let ac = &ruleset.ac_sets[*set_id];
                    let matched = values.iter().any(|s| ac.is_match(s));
                    debug!(set_id, matched, "MatchMulti");
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::MatchEq { literal_id } => {
                let values = pop_strings(&mut stack);
                if values.is_empty() {
                    stack.push(StackVal::Absent);
                } else {
                    let literal = &ruleset.literals[*literal_id];
                    let matched = values.iter().any(|s| s == literal);
                    stack.push(StackVal::Bool(matched));
                }
            }

            Instruction::Exists => {
                let values = pop_strings(&mut stack);
                let exists = !values.is_empty() && values.iter().any(|s| !s.is_empty());
                stack.push(StackVal::Bool(exists));
            }

            Instruction::Never => {
                let _ = pop_strings(&mut stack);
                stack.push(StackVal::Bool(false));
            }

            Instruction::LoadAnomalyScore => {
                stack.push(StackVal::Int(ctx.anomaly_score as i64));
            }

            Instruction::CmpGe { threshold } => {
                let val = pop_numeric_f64(&mut stack);
                stack.push(StackVal::Bool(val >= *threshold));
            }

            Instruction::MlScore { model_id } => {
                let model_name = &ruleset.ml_models[*model_id];
                let score = ctx.ml_scores.get(model_name).copied().unwrap_or(0.0);
                stack.push(StackVal::Float(score));
            }

            Instruction::RateCheck { window_id: _ } => {
                // TODO: integrate with sentinel-modules rate-limiter in Phase 2
                stack.push(StackVal::Bool(false));
            }

            Instruction::And => {
                let b = pop_bool(&mut stack);
                let a = pop_bool(&mut stack);
                stack.push(StackVal::Bool(a && b));
            }

            Instruction::Or => {
                let b = pop_bool(&mut stack);
                let a = pop_bool(&mut stack);
                stack.push(StackVal::Bool(a || b));
            }

            Instruction::Not => {
                match stack.pop() {
                    Some(StackVal::Absent) => stack.push(StackVal::Bool(false)),
                    Some(StackVal::Bool(b)) => stack.push(StackVal::Bool(!b)),
                    other => {
                        warn!("VM: Not: unexpected stack value {:?}", other);
                        stack.push(StackVal::Bool(false));
                    }
                }
            }

            Instruction::JmpIfFalse { offset } => {
                if let Some(StackVal::Bool(false)) = stack.last() {
                    let new_ip = (ip as i64 + *offset as i64) as usize;
                    ip = new_ip;
                    continue;
                }
            }

            Instruction::RuleEnd { rule_id } => {
                let fired = pop_bool(&mut stack);
                if fired {
                    if let Some(meta) = ruleset.rule_meta.get(rule_id) {
                        fire_rule(ctx, meta);
                    } else {
                        warn!(rule_id, "RuleEnd: no metadata found for rule");
                    }
                }
            }
        }
        ip += 1;
    }

    ctx.decision.clone()
}

fn fire_rule(ctx: &mut RequestContext, meta: &RuleMeta) {
    let phase = rule_phase_to_phase(meta.phase);

    match &meta.action {
        RuleAction::Block => {
            if ctx.decision != WafDecision::Block {
                ctx.decision = WafDecision::Block;
                ctx.block_reason = Some(meta.message.clone());
            }
        }
        RuleAction::Allow => {
            ctx.decision = WafDecision::Allow;
        }
        RuleAction::Challenge(_) => {
            if ctx.decision == WafDecision::Allow {
                ctx.decision = WafDecision::Challenge;
                ctx.block_reason = Some(meta.message.clone());
            }
        }
        RuleAction::Score | RuleAction::Log => {
            // No decision change; just accumulate score
        }
        RuleAction::Redirect(_) | RuleAction::PluginCall { .. } => {
            // TODO: implement in later phases
        }
    }

    // Add anomaly score
    if meta.score_delta > 0 {
        ctx.anomaly_score = ctx.anomaly_score.saturating_add(meta.score_delta as u32);
    }

    // Log the match
    ctx.rule_matches.push(RuleMatch {
        rule_id: meta.id.to_string(),
        message: meta.message.clone(),
        severity: map_severity(meta.severity),
        score: meta.score_delta.max(0) as u32,
        target: String::new(), // TODO: capture which target matched
        phase,
    });

    debug!(
        rule_id = meta.id,
        message = %meta.message,
        score_delta = meta.score_delta,
        "rule fired"
    );
}

// ---------------------------------------------------------------------------
// Stack helpers
// ---------------------------------------------------------------------------

fn pop_strings(stack: &mut Vec<StackVal>) -> Vec<String> {
    match stack.pop() {
        Some(StackVal::Strings(v)) => v,
        Some(other) => {
            warn!("VM: expected Strings on stack, got {:?}", other);
            vec![]
        }
        None => {
            warn!("VM: stack underflow on pop_strings");
            vec![]
        }
    }
}

fn pop_bool(stack: &mut Vec<StackVal>) -> bool {
    match stack.pop() {
        Some(StackVal::Bool(b)) => b,
        Some(StackVal::Absent) => false,
        Some(other) => {
            warn!("VM: expected Bool on stack, got {:?}", other);
            false
        }
        None => {
            warn!("VM: stack underflow on pop_bool");
            false
        }
    }
}

fn pop_numeric_f64(stack: &mut Vec<StackVal>) -> f64 {
    match stack.pop() {
        Some(StackVal::Int(v)) => v as f64,
        Some(StackVal::Float(v)) => v as f64,
        // TX variables are stored as strings; parse numerically when compared.
        // This makes @lt / @ge work against TX:DETECTION_PARANOIA_LEVEL etc.
        Some(StackVal::Strings(v)) => v
            .first()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0),
        Some(other) => {
            warn!("VM: expected numeric on stack, got {:?}", other);
            0.0
        }
        None => {
            warn!("VM: stack underflow on pop_numeric");
            0.0
        }
    }
}
