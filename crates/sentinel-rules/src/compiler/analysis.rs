use anyhow::{anyhow, Result};
use tracing::warn;

use crate::dsl::ast::{Operator, RuleFile, RuleItem, TargetExpr};

/// Semantic analysis pass: validate a parsed RuleFile.
///
/// - Checks that every rule has at least one target (unless it's an
///   anomaly_score / ml_score check, which is targetless by design).
/// - Warns about rules with a `score` action but no `score_delta`.
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

                // Warn if score action but no delta
                if matches!(rule.action, crate::dsl::ast::RuleAction::Score)
                    && rule.score_delta.is_none()
                {
                    warn!(
                        rule_id = rule.id,
                        "rule has action:score but no score field"
                    );
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
