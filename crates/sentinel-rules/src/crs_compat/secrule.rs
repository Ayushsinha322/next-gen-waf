use crate::dsl::ast::{RulePhase, RuleSeverity, SetVar, SetVarOp, Transform};

// ---------------------------------------------------------------------------
// Parsed CRS action attributes
// ---------------------------------------------------------------------------

/// Fully parsed CRS/ModSecurity action string.
#[derive(Debug, Default)]
pub struct CrsActions {
    pub id: Option<u32>,
    pub phase: Option<RulePhase>,
    pub action: CrsAction,
    /// True once a primary action keyword (block/pass/allow/deny) was seen.
    /// `log`/`nolog` are logging modifiers and must not overwrite a primary action.
    pub primary_action_set: bool,
    pub msg: Option<String>,
    pub severity: Option<RuleSeverity>,
    pub tags: Vec<String>,
    pub score_delta: Option<i32>,
    /// All `setvar` mutations targeting the per-request TX store, in declaration
    /// order. Unlike `score_delta` (which only tracks anomaly-score deltas for
    /// the fast blocking path), this preserves *every* `tx.*` write so category
    /// scores and correlation state are available to later rules.
    pub setvars: Vec<SetVar>,
    /// Whether this rule has a `chain` action (next SecRule is a chain member).
    pub chain: bool,
    /// Ordered list of transformations to apply to target values before matching.
    pub transforms: Vec<Transform>,
    /// CRS `skipAfter:MARKER` label (if present).
    pub skip_after: Option<String>,
    /// Whether `multiMatch` was specified — re-test operator at each transform step.
    pub multi_match: bool,
    /// Unrecognised action tokens (emitted as warnings).
    pub unknown: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum CrsAction {
    #[default]
    Pass,
    Block,
    Allow,
    Deny,
    Log,
    NoLog,
}

// ---------------------------------------------------------------------------
// Parse CRS operator string into (operator_name, pattern)
// ---------------------------------------------------------------------------

/// Parse a CRS operator string like `"@rx (?i)select"`, `"!@lt 10"`, or
/// `"@contains foo"`.  A leading `!` becomes a `!`-prefixed op name so the
/// caller can wrap the resulting operator in `Not(..)`.
pub fn parse_crs_operator(s: &str) -> (String, String) {
    let s = s.trim();
    let (negated, rest) = if let Some(r) = s.strip_prefix("!@") {
        (true, r)
    } else if let Some(r) = s.strip_prefix('@') {
        (false, r)
    } else if let Some(r) = s.strip_prefix('!') {
        // `!pattern` (no @) — treat the rest as a negated raw regex.
        return ("!rx".to_owned(), r.trim().to_owned());
    } else {
        // No @ prefix — treat as raw regex
        return ("rx".to_owned(), s.to_owned());
    };
    let mut parts = rest.splitn(2, ' ');
    let op = parts.next().unwrap_or("rx").to_lowercase();
    let pat = parts.next().unwrap_or("").to_owned();
    if negated {
        (format!("!{op}"), pat)
    } else {
        (op, pat)
    }
}

// ---------------------------------------------------------------------------
// Parse CRS target string into individual target tokens
// ---------------------------------------------------------------------------

/// Split a CRS target string like `"ARGS|ARGS_NAMES|REQUEST_HEADERS"` into
/// individual tokens, preserving `!` exclusions (currently ignored).
pub fn split_crs_targets(s: &str) -> Vec<String> {
    s.split('|')
        .map(|t| t.trim().trim_start_matches('!').to_uppercase())
        .filter(|t| !t.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// Parse CRS actions string
// ---------------------------------------------------------------------------

/// Parse a CRS actions string like
/// `"id:942100,phase:2,block,msg:'SQLi',severity:'CRITICAL',tag:'owasp-crs'"`.
pub fn parse_crs_actions(s: &str) -> CrsActions {
    let mut out = CrsActions::default();
    for token in split_crs_actions(s) {
        parse_action_token(&token, &mut out);
    }
    out
}

/// Split a CRS actions string on commas, respecting quoted strings.
fn split_crs_actions(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;

    for ch in s.chars() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ',' if !in_single && !in_double => {
                let t = current.trim().to_owned();
                if !t.is_empty() {
                    tokens.push(t);
                }
                current.clear();
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }
    let t = current.trim().to_owned();
    if !t.is_empty() {
        tokens.push(t);
    }
    tokens
}

fn parse_action_token(token: &str, out: &mut CrsActions) {
    let token = token.trim();

    // id:N
    if let Some(rest) = token.strip_prefix("id:") {
        out.id = rest.trim().parse().ok();
        return;
    }
    // phase:N
    if let Some(rest) = token.strip_prefix("phase:") {
        out.phase = rest
            .trim()
            .parse::<u8>()
            .ok()
            .and_then(RulePhase::from_modsec);
        return;
    }
    // msg:'...' or msg:"..."
    if let Some(rest) = token.strip_prefix("msg:") {
        out.msg = Some(unquote(rest.trim()));
        return;
    }
    // severity:CRITICAL
    if let Some(rest) = token.strip_prefix("severity:") {
        out.severity = parse_crs_severity(unquote(rest.trim()).as_str());
        return;
    }
    // tag:'...'
    if let Some(rest) = token.strip_prefix("tag:") {
        out.tags.push(unquote(rest.trim()));
        return;
    }
    // setvar:tx.anomaly_score=+5 or setvar:tx.anomaly_score=+%{tx.critical_anomaly_score}
    if let Some(rest) = token.strip_prefix("setvar:") {
        let rest = rest.trim();
        // Keep the fast anomaly-score path (drives ctx.anomaly_score directly).
        if let Some(delta) = parse_setvar_score_delta(rest) {
            // Sum all anomaly-score deltas in the rule (CRS v4 has exactly one per rule).
            out.score_delta = Some(out.score_delta.unwrap_or(0) + delta);
        }
        // Preserve the full TX-store mutation (arbitrary tx.* vars, macros, etc.)
        // so it executes at match time and is readable by later rules. Anomaly
        // score is intentionally recorded in BOTH: score_delta feeds the blocking
        // gate, the TX copy feeds TX:ANOMALY_SCORE reads — they don't interfere
        // (different fields).
        if let Some(sv) = parse_setvar(rest) {
            out.setvars.push(sv);
        }
        return;
    }
    // ver:'...' — version tag, add to tags
    if let Some(rest) = token.strip_prefix("ver:") {
        out.tags.push(format!("ver:{}", unquote(rest.trim())));
        return;
    }
    // logdata:'...' — skip
    if token.starts_with("logdata:") {
        return;
    }
    // rev:'...' — skip
    if token.starts_with("rev:") {
        return;
    }
    // maturity/accuracy — skip
    if token.starts_with("maturity:") || token.starts_with("accuracy:") {
        return;
    }
    // skip:N — skip N rules (not relevant to our rule ordering)
    if token.starts_with("skip:") {
        return; // silently ignore — no runtime skip-by-count
    }
    // skipAfter:MARKER — jump to named SecMarker when this rule fires
    if let Some(rest) = token.strip_prefix("skipAfter:") {
        out.skip_after = Some(unquote(rest.trim()));
        return;
    }

    // Simple action keywords
    match token.to_ascii_lowercase().as_str() {
        "block" | "deny" => {
            out.action = CrsAction::Block;
            out.primary_action_set = true;
        }
        "pass" => {
            out.action = CrsAction::Pass;
            out.primary_action_set = true;
        }
        "allow" => {
            out.action = CrsAction::Allow;
            out.primary_action_set = true;
        }
        // `log`/`nolog` are logging modifiers in CRS, NOT the primary action.
        // "block,log" → primary=block; "log" alone → Log (no primary set).
        "log" => {
            if !out.primary_action_set {
                out.action = CrsAction::Log;
            }
        }
        "nolog" => {
            if !out.primary_action_set {
                out.action = CrsAction::NoLog;
            }
        }
        "noauditlog" | "auditlog" | "capture" => {}
        // Transforms — applied in declaration order; t:none resets the list
        "t:none" => out.transforms.clear(),
        "t:lowercase" => out.transforms.push(Transform::Lowercase),
        "t:urldecodeuni" | "t:urldecode" => out.transforms.push(Transform::UrlDecodeUni),
        "t:removenulls" => out.transforms.push(Transform::RemoveNulls),
        "t:replacenulls" => out.transforms.push(Transform::ReplaceNulls),
        "t:htmlentitydecode" => out.transforms.push(Transform::HtmlEntityDecode),
        "t:removewhitespace" => out.transforms.push(Transform::RemoveWhitespace),
        "t:compresswhitespace" => out.transforms.push(Transform::CompressWhitespace),
        "t:jsdecode" => out.transforms.push(Transform::JsDecode),
        "t:cssdecode" => out.transforms.push(Transform::CssDecode),
        "t:base64decode" => out.transforms.push(Transform::Base64Decode),
        "t:hexdecode" => out.transforms.push(Transform::HexDecode),
        "t:normalisepath" | "t:normalizepath" => out.transforms.push(Transform::NormalisePath),
        "t:normalisepathwin" | "t:normalizepathwin" => {
            out.transforms.push(Transform::NormalisePathWin)
        }
        "t:trim" => out.transforms.push(Transform::Trim),
        "t:trimleft" => out.transforms.push(Transform::TrimLeft),
        "t:trimright" => out.transforms.push(Transform::TrimRight),
        "t:utf8tounicode" => out.transforms.push(Transform::Utf8ToUnicode),
        "t:removecommentschar" => out.transforms.push(Transform::RemoveCommentsChar),
        "t:removecomments" => out.transforms.push(Transform::RemoveComments),
        "t:replacecomments" => out.transforms.push(Transform::ReplaceComments),
        "t:cmdline" => out.transforms.push(Transform::CmdLine),
        "t:escapeseqdecode" => out.transforms.push(Transform::EscapeSeqDecode),
        "t:length" => out.transforms.push(Transform::Length),
        // An unsupported transform must NOT silently degrade a rule to matching
        // against under-normalized input — surface it so coverage gaps are
        // visible instead of becoming invisible evasion holes.
        other if other.starts_with("t:") => {
            tracing::warn!(
                transform = other,
                "unsupported CRS transform — dropped; rule will match under-normalized input"
            );
        }
        "multimatch" => out.multi_match = true,
        other if other.starts_with("ctl:") => {} // control directives — no-op
        "chain" => {
            out.chain = true;
        }
        other => {
            out.unknown.push(other.to_owned());
        }
    }
}

/// Try to parse a `setvar:tx.anomaly_score=+N` into a score delta.
///
/// Rules:
/// - Only `tx.anomaly_score` updates are extracted (category vars like
///   `tx.sql_injection_score` track subcategories but CRS rules also always
///   include a corresponding `tx.anomaly_score` delta, so we take that one).
/// - Only delta operations (`+N` or `-N`) are extracted; absolute assignments
///   (`=N` without sign) are ignored for scoring purposes.
fn parse_setvar_score_delta(s: &str) -> Option<i32> {
    // Strip quotes CRS sometimes wraps setvar values in
    let s = s.trim().trim_matches('\'');
    let (lhs, rhs) = s.split_once('=')?;
    let lhs = lhs.trim().to_ascii_lowercase();
    let rhs = rhs.trim();

    // Accumulate anomaly-score deltas only. CRS v4 detection rules raise the
    // per-paranoia-level inbound score (e.g. tx.inbound_anomaly_score_pl1),
    // which the 949 blocking-evaluation rule later sums. We map each of those
    // PL deltas straight onto the rule's score so the VM accumulates the total
    // anomaly score directly. Category scores (tx.sql_injection_score, etc.)
    // are deliberately ignored to avoid double-counting, and the legacy
    // tx.anomaly_score name is still honoured for older rule sets.
    let is_score_delta =
        lhs == "tx.anomaly_score" || lhs.starts_with("tx.inbound_anomaly_score_pl");
    if !is_score_delta {
        return None;
    }

    // Must start with + or - to be a delta operation.
    let (sign, num_str) = if let Some(rest) = rhs.strip_prefix('+') {
        (1i32, rest)
    } else if let Some(rest) = rhs.strip_prefix('-') {
        (-1i32, rest)
    } else {
        return None; // absolute assignment — not a delta
    };

    // Direct numeric: +5
    if let Ok(n) = num_str.trim().parse::<i32>() {
        return Some(sign * n);
    }

    // Variable reference: +%{tx.critical_anomaly_score}
    let num_str = num_str.trim();
    if num_str.starts_with("%{") && num_str.ends_with('}') {
        let inner = &num_str[2..num_str.len() - 1];
        let mapped = match inner.to_ascii_lowercase().as_str() {
            "tx.critical_anomaly_score" => Some(5),
            "tx.error_anomaly_score" => Some(4),
            "tx.warning_anomaly_score" => Some(3),
            "tx.notice_anomaly_score" => Some(2),
            _ => None,
        };
        return mapped.map(|v| sign * v);
    }

    None
}

/// Parse a full CRS `setvar` argument into a [`SetVar`] targeting the
/// per-request TX store.
///
/// Handles the CRS forms:
/// - `!tx.name`        → [`SetVarOp::Unset`]
/// - `tx.name=value`   → [`SetVarOp::Set`] (value may contain `%{...}` macros)
/// - `tx.name=+expr`   → [`SetVarOp::Add`] (numeric increment)
/// - `tx.name=-expr`   → [`SetVarOp::Sub`] (numeric decrement)
///
/// Only `tx.*` variables are modelled — other ModSecurity collections
/// (`ip.`, `session.`, `global.`) have no per-request store here, so they
/// return `None` and are dropped. The variable name is uppercased and stripped
/// of its `tx.` prefix to match the `TX:` read convention (see `token_to_target`).
fn parse_setvar(s: &str) -> Option<SetVar> {
    let s = s.trim().trim_matches('\'').trim_matches('"').trim();

    // Unset form: `!tx.name`
    if let Some(name) = s.strip_prefix('!') {
        return Some(SetVar {
            name: tx_key(name)?,
            op: SetVarOp::Unset,
        });
    }

    let (lhs, rhs) = s.split_once('=')?;
    let name = tx_key(lhs)?;
    let rhs = rhs.trim();

    let op = if let Some(rest) = rhs.strip_prefix('+') {
        SetVarOp::Add(rest.trim().to_owned())
    } else if let Some(rest) = rhs.strip_prefix('-') {
        SetVarOp::Sub(rest.trim().to_owned())
    } else {
        SetVarOp::Set(rhs.to_owned())
    };

    Some(SetVar { name, op })
}

/// Normalise a setvar LHS like `tx.sql_injection_score` into the uppercase
/// store key `SQL_INJECTION_SCORE`. Returns `None` for non-`tx.` collections.
fn tx_key(name: &str) -> Option<String> {
    let lower = name.trim().to_ascii_lowercase();
    let rest = lower.strip_prefix("tx.")?;
    if rest.is_empty() {
        return None;
    }
    Some(rest.to_ascii_uppercase())
}

fn parse_crs_severity(s: &str) -> Option<RuleSeverity> {
    match s.to_uppercase().as_str() {
        "CRITICAL" => Some(RuleSeverity::Critical),
        "ERROR" | "HIGH" => Some(RuleSeverity::High),
        "WARNING" | "MEDIUM" => Some(RuleSeverity::Medium),
        "NOTICE" | "LOW" => Some(RuleSeverity::Low),
        _ => None,
    }
}

/// Strip single or double quotes from a value.
fn unquote(s: &str) -> String {
    if (s.starts_with('\'') && s.ends_with('\'')) || (s.starts_with('"') && s.ends_with('"')) {
        s[1..s.len() - 1].to_owned()
    } else {
        s.to_owned()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_crs_operator() {
        let (op, pat) = parse_crs_operator("@rx (?i)select");
        assert_eq!(op, "rx");
        assert_eq!(pat, "(?i)select");
    }

    #[test]
    fn test_split_crs_targets() {
        let targets = split_crs_targets("ARGS|ARGS_NAMES|REQUEST_BODY");
        assert_eq!(targets, vec!["ARGS", "ARGS_NAMES", "REQUEST_BODY"]);
    }

    #[test]
    fn test_parse_crs_actions_basic() {
        let actions = parse_crs_actions(
            "id:942100,phase:2,block,msg:'SQL Injection',severity:'CRITICAL',tag:'owasp-crs'",
        );
        assert_eq!(actions.id, Some(942100));
        assert_eq!(actions.phase, Some(RulePhase::RequestBody));
        assert_eq!(actions.action, CrsAction::Block);
        assert_eq!(actions.msg.as_deref(), Some("SQL Injection"));
        assert_eq!(actions.severity, Some(RuleSeverity::Critical));
        assert!(actions.tags.iter().any(|t| t == "owasp-crs"));
    }

    #[test]
    fn test_parse_crs_actions_setvar() {
        let actions = parse_crs_actions("id:942100,phase:2,pass,setvar:tx.anomaly_score=+5");
        assert_eq!(actions.score_delta, Some(5));
        // The anomaly-score setvar is ALSO captured in the TX-store list so it is
        // readable via TX:ANOMALY_SCORE, without affecting the score_delta path.
        assert_eq!(
            actions.setvars,
            vec![SetVar {
                name: "ANOMALY_SCORE".to_owned(),
                op: SetVarOp::Add("5".to_owned()),
            }]
        );
    }

    #[test]
    fn test_parse_setvar_category_score_not_counted_as_anomaly() {
        // A category-score setvar must be preserved in the TX store but NOT
        // treated as an anomaly-score delta (that would double-count).
        let actions = parse_crs_actions("id:942100,phase:2,pass,setvar:tx.sql_injection_score=+5");
        assert_eq!(actions.score_delta, None);
        assert_eq!(
            actions.setvars,
            vec![SetVar {
                name: "SQL_INJECTION_SCORE".to_owned(),
                op: SetVarOp::Add("5".to_owned()),
            }]
        );
    }

    #[test]
    fn test_parse_setvar_all_forms() {
        assert_eq!(
            parse_setvar("tx.foo=+%{tx.critical_anomaly_score}"),
            Some(SetVar {
                name: "FOO".to_owned(),
                op: SetVarOp::Add("%{tx.critical_anomaly_score}".to_owned()),
            })
        );
        assert_eq!(
            parse_setvar("tx.bar=-2"),
            Some(SetVar {
                name: "BAR".to_owned(),
                op: SetVarOp::Sub("2".to_owned()),
            })
        );
        assert_eq!(
            parse_setvar("tx.msg=blocked"),
            Some(SetVar {
                name: "MSG".to_owned(),
                op: SetVarOp::Set("blocked".to_owned()),
            })
        );
        assert_eq!(
            parse_setvar("!tx.foo"),
            Some(SetVar {
                name: "FOO".to_owned(),
                op: SetVarOp::Unset,
            })
        );
        // Non-tx collections are not modelled → dropped.
        assert_eq!(parse_setvar("ip.reput_block_flag=1"), None);
    }
}
