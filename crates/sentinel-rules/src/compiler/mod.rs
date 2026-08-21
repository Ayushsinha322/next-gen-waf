pub mod analysis;
pub mod emitter;
pub mod optimizer;
pub mod vm;

use anyhow::{Context, Result};
use regex::Regex;
use tracing::debug;

use crate::dsl::ast::{
    CmpOp, Directive, Operator, RuleDef, RuleFile, RuleItem, RuleSeverity, TargetCombinator,
    TargetExpr, Transform, VirtualPatch,
};
use emitter::{CompiledRuleSet, Instruction, RuleCoverage, RuleMeta, TargetSpec};
use optimizer::build_ac;

// ---------------------------------------------------------------------------
// Compiler state
// ---------------------------------------------------------------------------

struct CompilerState {
    patterns: Vec<Regex>,
    ac_set_words: Vec<Vec<String>>,
    literals: Vec<String>,
    ml_models: Vec<String>,
    plugin_names: Vec<String>,
}

impl CompilerState {
    fn new() -> Self {
        Self {
            patterns: Vec::new(),
            ac_set_words: Vec::new(),
            literals: Vec::new(),
            ml_models: Vec::new(),
            plugin_names: Vec::new(),
        }
    }

    fn intern_pattern(&mut self, pattern: &str) -> Result<usize> {
        // Reuse identical patterns
        if let Some(idx) = self.patterns.iter().position(|r| r.as_str() == pattern) {
            return Ok(idx);
        }
        let re = Regex::new(pattern).with_context(|| format!("invalid regex: {pattern}"))?;
        let idx = self.patterns.len();
        self.patterns.push(re);
        Ok(idx)
    }

    fn intern_ac_set(&mut self, words: Vec<String>) -> usize {
        // Reuse identical word lists
        if let Some(idx) = self.ac_set_words.iter().position(|w| w == &words) {
            return idx;
        }
        let idx = self.ac_set_words.len();
        self.ac_set_words.push(words);
        idx
    }

    fn intern_literal(&mut self, lit: String) -> usize {
        if let Some(idx) = self.literals.iter().position(|l| l == &lit) {
            return idx;
        }
        let idx = self.literals.len();
        self.literals.push(lit);
        idx
    }

    fn intern_ml_model(&mut self, model: &str) -> usize {
        if let Some(idx) = self.ml_models.iter().position(|m| m == model) {
            return idx;
        }
        let idx = self.ml_models.len();
        self.ml_models.push(model.to_owned());
        idx
    }
}

// ---------------------------------------------------------------------------
// Public compile function
// ---------------------------------------------------------------------------

/// Compile a (possibly mutated by analysis) `RuleFile` into a `CompiledRuleSet`.
pub fn compile(file: RuleFile) -> Result<CompiledRuleSet> {
    let mut state = CompilerState::new();
    let mut phase_programs: [Vec<Instruction>; 7] = Default::default();
    let mut rule_meta: std::collections::HashMap<u32, RuleMeta> = std::collections::HashMap::new();

    // Process items in source order — CRS skip-gate correctness depends on it.
    //
    // CRS structures each rule file as:
    //   skip-gate(@lt 1)  ←── fires if PL < 1; jumps to END marker
    //   PL1 rules
    //   skip-gate(@lt 2)  ←── fires if PL < 2; jumps to END marker
    //   PL2 rules
    //   …
    //   SecMarker END-REQUEST-xxx
    //
    // Sorting by rule_id would move all skip-gates (small IDs like 941012)
    // ahead of all detection rules (larger IDs like 941100+), causing the
    // skip-gate to fire and skip past every detection rule.
    //
    // SecMarker instructions are emitted into EVERY phase program at the
    // current source position so that skip-gates in any phase can find their
    // target (CRS uses the same marker name for phase-1 and phase-2 gates).

    let mut dropped: Vec<(u32, String)> = Vec::new();
    let mut disabled: Vec<u32> = Vec::new();
    for item in file.items {
        match item {
            RuleItem::Rule(rule) => {
                let rule_id = rule.id;
                let phase = rule.phase;
                match compile_rule(&rule, &mut state) {
                    Ok((instrs, meta)) => {
                        rule_meta.insert(meta.id, meta);
                        phase_programs[phase as usize].extend(instrs);
                        // A rule imported with an unsupported operator compiles
                        // but can never match — record it as a coverage gap so
                        // it isn't silently counted as "loaded protection".
                        if matches!(rule.operator, Operator::Never) {
                            disabled.push(rule_id);
                        }
                    }
                    Err(e) => {
                        dropped.push((rule_id, format!("{e:#}")));
                        tracing::warn!(rule_id, "skipping rule (compile error): {e:#}");
                    }
                }
            }
            RuleItem::VirtualPatch(vp) => {
                let phase = vp.phase;
                let cve = vp.cve.clone();
                match compile_virtual_patch(&vp, &mut state) {
                    Ok((instrs, meta)) => {
                        let vp_id: u32 = cve_to_id(&vp.cve);
                        rule_meta.insert(vp_id, meta);
                        phase_programs[phase as usize].extend(instrs);
                    }
                    Err(e) => {
                        dropped.push((cve_to_id(&cve), format!("{e:#}")));
                        tracing::warn!(cve = %cve, "skipping virtual-patch (compile error): {e:#}");
                    }
                }
            }
            RuleItem::Directive(Directive::SecMarker(name)) => {
                // Emit the marker into every phase program at the current
                // position so skip-gates in phase 1 and phase 2 both find it.
                for prog in phase_programs.iter_mut() {
                    prog.push(Instruction::Marker(name.clone()));
                }
            }
            RuleItem::Directive(_) => {
                // Other directives handled at load time, not compiled to bytecode.
            }
        }
    }
    if !dropped.is_empty() || !disabled.is_empty() {
        let dropped_ids: Vec<u32> = dropped.iter().map(|(id, _)| *id).collect();
        tracing::warn!(
            dropped = dropped.len(),
            disabled = disabled.len(),
            dropped_rule_ids = ?dropped_ids,
            disabled_rule_ids = ?disabled,
            "rule coverage gap: these rules are NOT enforced (dropped on compile error or unsupported operator) — \
             review before relying on full CRS coverage"
        );
    }

    // Build Aho-Corasick automata from interned word-list tables.
    let ac_sets = state
        .ac_set_words
        .iter()
        .map(|words| build_ac(words))
        .collect::<Result<Vec<_>, _>>()?;

    debug!(
        rules = rule_meta.len(),
        patterns = state.patterns.len(),
        ac_sets = ac_sets.len(),
        "compiled ruleset"
    );

    Ok(CompiledRuleSet {
        phase_programs,
        patterns: state.patterns,
        ac_sets,
        literals: state.literals,
        ml_models: state.ml_models,
        plugin_names: state.plugin_names,
        rule_meta,
        coverage: RuleCoverage { dropped, disabled },
    })
}

// ---------------------------------------------------------------------------
// Rule compilation helpers
// ---------------------------------------------------------------------------

fn compile_rule(rule: &RuleDef, state: &mut CompilerState) -> Result<(Vec<Instruction>, RuleMeta)> {
    let mut instrs: Vec<Instruction> = Vec::new();
    let meta = RuleMeta {
        id: rule.id,
        message: rule.message.clone().unwrap_or_default(),
        severity: rule.severity.unwrap_or(RuleSeverity::Notice),
        score_delta: rule.score_delta.unwrap_or(0),
        action: rule.action.clone(),
        tags: rule.tags.clone(),
        phase: rule.phase,
        skip_after: rule.skip_after.clone(),
        setvars: rule.setvars.clone(),
    };

    emit_condition(
        &rule.targets,
        &rule.operator,
        &rule.transforms,
        rule.multi_match,
        state,
        &mut instrs,
    )?;

    // Chain conditions: AND-ed with the primary condition result.
    // Transforms from the parent rule also apply to chain member targets.
    for chain in &rule.chain_conditions {
        emit_condition(
            &chain.targets,
            &chain.operator,
            &rule.transforms,
            rule.multi_match,
            state,
            &mut instrs,
        )?;
        instrs.push(Instruction::And);
    }

    instrs.push(Instruction::RuleEnd { rule_id: rule.id });

    Ok((instrs, meta))
}

fn compile_virtual_patch(
    vp: &VirtualPatch,
    state: &mut CompilerState,
) -> Result<(Vec<Instruction>, RuleMeta)> {
    let vp_id = cve_to_id(&vp.cve);
    let mut instrs: Vec<Instruction> = Vec::new();
    let meta = RuleMeta {
        id: vp_id,
        message: vp
            .message
            .clone()
            .unwrap_or_else(|| format!("Virtual patch: {}", vp.cve)),
        severity: RuleSeverity::Critical,
        score_delta: 0,
        action: vp.action.clone(),
        tags: vec![format!("virtual-patch/{}", vp.cve)],
        phase: vp.phase,
        skip_after: None,
        setvars: Vec::new(),
    };

    emit_condition(&vp.targets, &vp.operator, &[], false, state, &mut instrs)?;
    instrs.push(Instruction::RuleEnd { rule_id: vp_id });

    Ok((instrs, meta))
}

/// Emit instructions that evaluate `targets op operator` → Bool on stack.
///
/// For multi-target expressions like `ARGS | REQUEST_BODY`, this emits:
/// ```text
/// LoadTarget(Args)  [ApplyTransforms]  MatchRx(0)
/// LoadTarget(RequestBody)  [ApplyTransforms]  MatchRx(0)
/// Or
/// ```
fn emit_condition(
    targets: &[TargetExpr],
    operator: &Operator,
    transforms: &[Transform],
    multi_match: bool,
    state: &mut CompilerState,
    instrs: &mut Vec<Instruction>,
) -> Result<()> {
    // Special operators that don't use targets
    match operator {
        Operator::AnomalyScore { op, threshold } => {
            instrs.push(Instruction::LoadAnomalyScore);
            let t = match op {
                CmpOp::Gt => *threshold as f64 + 1.0,
                _ => *threshold as f64,
            };
            instrs.push(Instruction::CmpGe { threshold: t });
            return Ok(());
        }
        Operator::MlScore {
            model,
            op: _,
            threshold,
        } => {
            let model_id = state.intern_ml_model(model);
            instrs.push(Instruction::MlScore { model_id });
            instrs.push(Instruction::CmpGe {
                threshold: *threshold as f64,
            });
            return Ok(());
        }
        Operator::RateLimit { .. } => {
            instrs.push(Instruction::RateCheck { window_id: 0 });
            return Ok(());
        }
        _ => {}
    }

    if targets.is_empty() {
        // Emit a constant false — rule will never fire.
        // (analysis.rs should have caught this)
        instrs.push(Instruction::LoadTarget(TargetSpec::RequestUri));
        instrs.push(Instruction::MatchEq {
            literal_id: state.intern_literal("__never__".to_owned()),
        });
        return Ok(());
    }

    // Emit one "load+[transforms]+match" per target, combining with And/Or combinators.
    for (i, tex) in targets.iter().enumerate() {
        let spec = TargetSpec::from(&tex.target);
        instrs.push(Instruction::LoadTarget(spec));
        if !transforms.is_empty() {
            instrs.push(Instruction::ApplyTransforms {
                transforms: transforms.to_vec(),
                multi_match,
            });
        }
        emit_operator_match(operator, state, instrs)?;

        // Apply combinator from previous target
        if i > 0 {
            let prev_combinator = targets
                .get(i - 1)
                .and_then(|t| t.combinator)
                .unwrap_or(TargetCombinator::Or);
            match prev_combinator {
                TargetCombinator::Or => instrs.push(Instruction::Or),
                TargetCombinator::And => instrs.push(Instruction::And),
            }
        }
    }

    Ok(())
}

/// Emit the match instruction(s) for a single target (top of stack = StrVec).
fn emit_operator_match(
    operator: &Operator,
    state: &mut CompilerState,
    instrs: &mut Vec<Instruction>,
) -> Result<()> {
    match operator {
        Operator::Rx(pat) => {
            let pattern_id = state.intern_pattern(pat)?;
            instrs.push(Instruction::MatchRx { pattern_id });
        }
        Operator::ContainsWord(words) => {
            let set_id = state.intern_ac_set(words.clone());
            instrs.push(Instruction::MatchMulti { set_id });
        }
        Operator::Eq(val) => {
            let literal_id = state.intern_literal(val.clone());
            instrs.push(Instruction::MatchEq { literal_id });
        }
        Operator::Ge(n) => {
            instrs.push(Instruction::CmpGe {
                threshold: *n as f64,
            });
        }
        Operator::Interpolated { cmp, raw } => {
            let raw_id = state.intern_literal(raw.clone());
            instrs.push(Instruction::MatchInterpolated { cmp: *cmp, raw_id });
        }
        Operator::Exists => {
            instrs.push(Instruction::Exists);
        }
        Operator::DetectSqli => {
            instrs.push(Instruction::DetectSqli);
        }
        Operator::DetectXss => {
            instrs.push(Instruction::DetectXss);
        }
        Operator::OffDomainUrl => {
            instrs.push(Instruction::DetectOffDomainUrl);
        }
        Operator::SsrfUrl => {
            instrs.push(Instruction::DetectSsrfUrl);
        }
        Operator::IpMatch(cidrs) => {
            instrs.push(Instruction::IpMatch {
                cidrs: cidrs.clone(),
            });
        }
        Operator::Never => {
            instrs.push(Instruction::Never);
        }
        Operator::Not(inner) => {
            emit_operator_match(inner, state, instrs)?;
            instrs.push(Instruction::Not);
        }
        // Non-target operators handled above in emit_condition
        Operator::AnomalyScore { .. } | Operator::MlScore { .. } | Operator::RateLimit { .. } => {}
    }
    Ok(())
}

/// Map a CVE string to a synthetic u32 rule ID using a simple hash.
fn cve_to_id(cve: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in cve.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    // Ensure it doesn't collide with standard rule IDs (< 1_000_000)
    (h % 0x0FFF_FFFF) + 1_000_000
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::parser::parse_rule_file;

    #[test]
    fn compile_sqli_rule() {
        let src = r#"
rule 942100 {
    phase    : request_body
    targets  : ARGS
    operator : rx /(?i)(select|union|insert|update|delete|drop|exec)\s/
    score    : +5
    severity : critical
    message  : "SQL injection attempt"
    action   : score
}
"#;
        let file = parse_rule_file(src).expect("parse");
        let ruleset = compile(file).expect("compile");
        assert_eq!(ruleset.rule_meta.len(), 1);
        assert!(!ruleset.patterns.is_empty());
    }

    #[test]
    fn compile_contains_word_rule() {
        let src = r#"
rule 942101 {
    phase    : request_body
    targets  : ARGS
    operator : contains_word ["xp_cmdshell", "exec("]
    score    : +8
    action   : block
    message  : "SQL stored procedure injection"
}
"#;
        let file = parse_rule_file(src).expect("parse");
        let ruleset = compile(file).expect("compile");
        assert_eq!(ruleset.ac_sets.len(), 1);
    }
}
