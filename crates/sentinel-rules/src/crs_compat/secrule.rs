use crate::dsl::ast::{RulePhase, RuleSeverity};

// ---------------------------------------------------------------------------
// Parsed CRS action attributes
// ---------------------------------------------------------------------------

/// Fully parsed CRS/ModSecurity action string.
#[derive(Debug, Default)]
pub struct CrsActions {
    pub id: Option<u32>,
    pub phase: Option<RulePhase>,
    pub action: CrsAction,
    pub msg: Option<String>,
    pub severity: Option<RuleSeverity>,
    pub tags: Vec<String>,
    pub score_delta: Option<i32>,
    /// Whether this rule has a `chain` action (next SecRule is a chain member).
    pub chain: bool,
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
        out.phase = rest.trim().parse::<u8>().ok().and_then(RulePhase::from_modsec);
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
    // setvar:tx.anomaly_score=+5 or setvar:tx.sql_injection_score=+%{...}
    if let Some(rest) = token.strip_prefix("setvar:") {
        if let Some(delta) = parse_setvar_score_delta(rest.trim()) {
            out.score_delta = Some(delta);
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
    // skip/skipAfter — skip chains for now
    if token.starts_with("skip:") || token.starts_with("skipAfter:") {
        out.unknown.push(token.to_owned());
        return;
    }

    // Simple action keywords
    match token.to_lowercase().as_str() {
        "block" | "deny" => out.action = CrsAction::Block,
        "pass" => out.action = CrsAction::Pass,
        "allow" => out.action = CrsAction::Allow,
        "log" => out.action = CrsAction::Log,
        "nolog" => out.action = CrsAction::NoLog,
        "noauditlog" | "auditlog" | "capture" | "t:none" | "t:lowercase"
        | "t:urlDecodeUni" | "t:htmlEntityDecode" | "t:removeNulls"
        | "t:removeWhitespace" | "t:cssDecode" | "t:jsDecode" => {
            // Transformation / log flags — silently skip
        }
        other if other.starts_with("t:") => {} // any other transform
        other if other.starts_with("ctl:") => {} // control directives
        "chain" => {
            out.chain = true;
        }
        other => {
            out.unknown.push(other.to_owned());
        }
    }
}

/// Try to parse a `setvar:tx.something=+N` into a score delta.
fn parse_setvar_score_delta(s: &str) -> Option<i32> {
    // We care about patterns like:
    //   tx.anomaly_score=+5
    //   tx.critical_anomaly_score=+5
    //   tx.sql_injection_score=+5
    // and ignore references like `+%{tx.critical_anomaly_score}`.
    let (_lhs, rhs) = s.split_once('=')?;
    let rhs = rhs.trim();
    if rhs.starts_with('%') {
        return None; // variable reference — skip
    }
    rhs.parse::<i32>().ok()
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
    if (s.starts_with('\'') && s.ends_with('\''))
        || (s.starts_with('"') && s.ends_with('"'))
    {
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
        let actions =
            parse_crs_actions("id:942100,phase:2,pass,setvar:tx.anomaly_score=+5");
        assert_eq!(actions.score_delta, Some(5));
    }
}
