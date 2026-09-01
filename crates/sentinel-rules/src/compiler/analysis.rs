use anyhow::{anyhow, Result};
use tracing::{debug, warn};

use crate::dsl::ast::{Operator, RuleFile, RuleItem, TargetExpr};

/// Semantic analysis pass: validate a parsed RuleFile.
///
/// - Checks that every rule has at least one target (unless it's an
///   anomaly_score / ml_score check, which is targetless by design).
/// - Warns about rules with a `score` action, no `score_delta` AND a message —
///   those are logged but can never contribute to a block. The message-less case
///   is a deliberate CRS skip-gate and is logged at debug.
/// - Deduplicates repeated rule IDs (keeps last, warn).
pub fn analyse(file: &mut RuleFile) -> Result<()> {
    let mut seen_ids: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    let mut errors: Vec<String> = Vec::new();

    for (idx, item) in file.items.iter_mut().enumerate() {
        match item {
            RuleItem::Rule(rule) => {
                // Check duplicate IDs
                if let Some(prev_idx) = seen_ids.insert(rule.id, idx) {
                    warn!(
                        rule_id = rule.id,
                        prev_idx, "duplicate rule ID; keeping latest"
                    );
                }

                // Validate targets vs operator
                validate_targets_operator(rule.id, &rule.targets, &rule.operator, &mut errors);

                // A `score` action with no delta means the rule contributes 0 to
                // the anomaly score. Whether that is a defect depends entirely on
                // whether the rule has a MESSAGE:
                //
                //   - No message: a CRS paranoia-level skip-gate or counter
                //     (`pass,nolog`, ids like 942011-942018 and 921170). Silence
                //     is its whole purpose — the VM applies its setvars before the
                //     is_silent check, so category scores still accumulate. 108
                //     such rules ship in CRS 4.7, and warning about each of them
                //     twice per import buried the ten warnings that DID matter
                //     under 216 that did not, at 20:1. A channel nobody can read
                //     is the same as no channel.
                //
                //   - Has a message: a real detection rule that will be RECORDED
                //     when it fires but can never move the request toward a block.
                //     That is worth waking someone for.
                if has_score_gap(rule) {
                    if score_gap_is_actionable(rule) {
                        warn!(
                            rule_id = rule.id,
                            "rule will be logged but can never contribute to the anomaly score: \
                             action:score with no score field"
                        );
                    } else {
                        debug!(
                            rule_id = rule.id,
                            "silent score-gate rule (no message, no score) — expected for CRS \
                             paranoia gates and counters"
                        );
                    }
                }
            }
            RuleItem::VirtualPatch(vp) => {
                validate_vp_targets_operator(&vp.cve, &vp.targets, &vp.operator, &mut errors);
            }
            RuleItem::Directive(_) => {}
        }
    }

    if !errors.is_empty() {
        return Err(anyhow!("semantic errors:\n{}", errors.join("\n")));
    }
    Ok(())
}

/// A `score` action carrying no delta: the rule contributes 0 to the anomaly
/// score when it fires.
pub(crate) fn has_score_gap(rule: &crate::dsl::ast::RuleDef) -> bool {
    matches!(rule.action, crate::dsl::ast::RuleAction::Score) && rule.score_delta.is_none()
}

/// Is that gap a DEFECT, or the intended shape of a silent gate?
///
/// The message decides it. A rule with a message is recorded in `rule_matches`
/// when it fires (see the VM's `is_silent`), so an operator will see it in the
/// log and reasonably expect it to count toward a block — and it never will. A
/// rule with no message is a CRS paranoia skip-gate or counter, whose whole job
/// is to set a variable quietly; 108 of them ship in CRS 4.7.
pub(crate) fn score_gap_is_actionable(rule: &crate::dsl::ast::RuleDef) -> bool {
    has_score_gap(rule) && rule.message.as_deref().is_some_and(|m| !m.is_empty())
}

fn validate_targets_operator(
    id: u32,
    targets: &[TargetExpr],
    op: &Operator,
    errors: &mut Vec<String>,
) {
    // anomaly_score and ml_score don't need targets
    if matches!(
        op,
        Operator::AnomalyScore { .. } | Operator::MlScore { .. } | Operator::RateLimit { .. }
    ) {
        return;
    }
    if targets.is_empty() {
        errors.push(format!("rule {id}: operator requires at least one target"));
    }
}

fn validate_vp_targets_operator(
    cve: &str,
    targets: &[TargetExpr],
    op: &Operator,
    errors: &mut Vec<String>,
) {
    if matches!(op, Operator::AnomalyScore { .. } | Operator::MlScore { .. }) {
        return;
    }
    if targets.is_empty() {
        errors.push(format!(
            "virtual_patch {cve}: operator requires at least one target"
        ));
    }
}

/// Which score-gap rules deserve a WARN.
///
/// 108 CRS 4.7 rules are `score`-with-no-delta by design (paranoia skip-gates and
/// counters). Warning about every one of them — twice per import, since each site
/// compiles the corpus — produced 216 WARN lines that buried the 10 that mattered
/// at 20:1. Both sets were invisible anyway behind a RUST_LOG filter that omitted
/// this crate; once it was fixed, the noise was the first thing visible.
#[cfg(test)]
mod score_gap_tests {
    use super::*;
    use crate::dsl::ast::{RuleAction, RuleDef};

    fn score_rule(id: u32, message: Option<&str>, delta: Option<i32>) -> RuleDef {
        RuleDef {
            id,
            action: RuleAction::Score,
            score_delta: delta,
            message: message.map(str::to_owned),
            ..Default::default()
        }
    }

    /// A CRS paranoia skip-gate: `pass,nolog`, no message, no score. Silence is
    /// its purpose — the VM applies its setvars BEFORE the is_silent check, so
    /// category scores still accumulate.
    #[test]
    fn a_messageless_score_gate_is_not_actionable() {
        let gate = score_rule(942011, None, None);
        assert!(has_score_gap(&gate));
        assert!(
            !score_gap_is_actionable(&gate),
            "CRS skip-gates must not warn; 108 of them ship and the noise hid the \
             four rules that genuinely could not fire"
        );
        // An empty string is the same case as absent.
        assert!(!score_gap_is_actionable(&score_rule(
            942012,
            Some(""),
            None
        )));
    }

    /// A real detection rule that lost its score: it WILL appear in the log when
    /// it fires (it has a message, so the VM records it) and can never move the
    /// request toward a block. That mismatch is worth waking someone for.
    #[test]
    fn a_scoreless_rule_with_a_message_is_actionable() {
        let rule = score_rule(942100, Some("SQL Injection Attack Detected"), None);
        assert!(
            score_gap_is_actionable(&rule),
            "a rule that is logged but can never contribute to a block must warn"
        );
    }

    /// A rule with a delta is not a gap at all, message or no message.
    #[test]
    fn a_rule_with_a_score_is_never_reported() {
        for msg in [None, Some("SQL Injection Attack Detected")] {
            let rule = score_rule(942100, msg, Some(5));
            assert!(!has_score_gap(&rule));
            assert!(!score_gap_is_actionable(&rule));
        }
    }
}
