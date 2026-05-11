pub mod analysis;
pub mod emitter;
pub mod optimizer;
pub mod vm;

use anyhow::{Context, Result};
use regex::Regex;
use tracing::debug;

use crate::dsl::ast::{
    CmpOp, Operator, RuleDef, RuleFile, RuleItem, RulePhase, RuleSeverity,
    TargetCombinator, TargetExpr, VirtualPatch,
};
use emitter::{CompiledRuleSet, Instruction, RuleMeta, TargetSpec};
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
        let re = Regex::new(pattern)
            .with_context(|| format!("invalid regex: {pattern}"))?;
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
    let mut rule_meta: std::collections::HashMap<u32, RuleMeta> =
        std::collections::HashMap::new();

    // Sort items so rules within a phase are ordered by rule_id (CRS requirement).
    let mut rules: Vec<(RulePhase, u32, Vec<Instruction>, RuleMeta)> = Vec::new();

    let mut skipped = 0usize;
    for item in file.items {
        match item {
            RuleItem::Rule(rule) => {
                let rule_id = rule.id;
                match compile_rule(&rule, &mut state) {
                    Ok((instrs, meta)) => rules.push((rule.phase, rule.id, instrs, meta)),
                    Err(e) => {
                        skipped += 1;
                        tracing::warn!(rule_id, "skipping rule (compile error): {e:#}");
                    }
                }
            }
            RuleItem::VirtualPatch(vp) => {
                let cve = vp.cve.clone();
                match compile_virtual_patch(&vp, &mut state) {
                    Ok((instrs, meta)) => {
                        let vp_id: u32 = cve_to_id(&vp.cve);
                        rules.push((vp.phase, vp_id, instrs, meta));
                    }
                    Err(e) => {
                        skipped += 1;
                        tracing::warn!(cve = %cve, "skipping virtual-patch (compile error): {e:#}");
                    }
                }
            }
            RuleItem::Directive(_) => {
                // Directives are handled at load time, not compiled to bytecode.
            }
        }
    }
    if skipped > 0 {
        tracing::warn!(skipped, "compiler: skipped rules due to errors");
    }

    // Sort by (phase, rule_id) for deterministic per-phase ordering.
    rules.sort_by_key(|(phase, id, _, _)| (*phase as usize, *id));

    for (phase, _, instrs, meta) in rules {
        rule_meta.insert(meta.id, meta);
        let prog = &mut phase_programs[phase as usize];
        prog.extend(instrs);
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
    })
}

// ---------------------------------------------------------------------------
// Rule compilation helpers
// ---------------------------------------------------------------------------

fn compile_rule(
    rule: &RuleDef,
    state: &mut CompilerState,
) -> Result<(Vec<Instruction>, RuleMeta)> {
    let mut instrs: Vec<Instruction> = Vec::new();
    let meta = RuleMeta {
        id: rule.id,
        message: rule.message.clone().unwrap_or_default(),
        severity: rule.severity.unwrap_or(RuleSeverity::Notice),
        score_delta: rule.score_delta.unwrap_or(0),
        action: rule.action.clone(),
        tags: rule.tags.clone(),
        phase: rule.phase,
    };

    emit_condition(&rule.targets, &rule.operator, state, &mut instrs)?;

    // Chain conditions: each is AND-ed with the accumulated result.
    for chain in &rule.chain_conditions {
        emit_condition(&chain.targets, &chain.operator, state, &mut instrs)?;
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
        message: vp.message.clone().unwrap_or_else(|| format!("Virtual patch: {}", vp.cve)),
        severity: RuleSeverity::Critical,
        score_delta: 0,
        action: vp.action.clone(),
        tags: vec![format!("virtual-patch/{}", vp.cve)],
        phase: vp.phase,
    };

    emit_condition(&vp.targets, &vp.operator, state, &mut instrs)?;
    instrs.push(Instruction::RuleEnd { rule_id: vp_id });

    Ok((instrs, meta))
}

/// Emit instructions that evaluate `targets op operator` → Bool on stack.
///
/// For multi-target expressions like `ARGS | REQUEST_BODY`, this emits:
/// ```text
/// LoadTarget(Args)  MatchRx(0)
/// LoadTarget(RequestBody)  MatchRx(0)
/// Or
/// ```
fn emit_condition(
    targets: &[TargetExpr],
    operator: &Operator,
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
        Operator::MlScore { model, op: _, threshold } => {
            let model_id = state.intern_ml_model(model);
            instrs.push(Instruction::MlScore { model_id });
            instrs.push(Instruction::CmpGe { threshold: *threshold as f64 });
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

    // Emit one "load+match" per target, combining with And/Or combinators.
    for (i, tex) in targets.iter().enumerate() {
        let spec = TargetSpec::from(&tex.target);
        instrs.push(Instruction::LoadTarget(spec));
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
            instrs.push(Instruction::CmpGe { threshold: *n as f64 });
        }
        Operator::Exists => {
            instrs.push(Instruction::Exists);
        }
        Operator::Not(inner) => {
            emit_operator_match(inner, state, instrs)?;
            instrs.push(Instruction::Not);
        }
        // Non-target operators handled above in emit_condition
        Operator::AnomalyScore { .. }
        | Operator::MlScore { .. }
        | Operator::RateLimit { .. } => {}
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
        assert!(ruleset.patterns.len() >= 1);
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
