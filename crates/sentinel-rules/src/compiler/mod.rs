pub mod analysis;
pub mod emitter;
pub mod optimizer;
pub mod vm;

use anyhow::{Context, Result};
use regex::Regex;
use tracing::debug;

use crate::dsl::ast::{
    CmpOp, Directive, Operator, RuleDef, RuleFile, RuleItem, RuleSeverity, SetVar,
    TargetCombinator, TargetExclusion, TargetExpr, Transform, VirtualPatch,
};
use emitter::{CompiledRuleSet, Instruction, RuleCoverage, RuleMeta, TargetSpec};
use optimizer::build_ac;

// ---------------------------------------------------------------------------
// Compiler state
// ---------------------------------------------------------------------------

/// Translate the PCRE constructs that `regex` rejects but ModSecurity accepts.
///
/// CRS is written for PCRE. Two of its habits are hard errors for the `regex`
/// crate, and a rule that fails to compile is SKIPPED — it logs a warning at
/// startup and then simply is not there. Six shipped CRS rules were silently
/// absent on .71 because of this, found by reading the data plane's own logs:
///
/// | rule            | what was missing              |
/// |-----------------|-------------------------------|
/// | 921200          | LDAP injection                |
/// | 932170, 932171  | Shellshock                    |
/// | 933170, 933180  | PHP object / code injection   |
/// | 941380          | AngularJS template XSS        |
///
/// The two constructs:
///
/// 1. **A literal `{` that does not begin a quantifier.** PCRE treats `{` as
///    literal when it cannot read a repetition after it, so `{{.*?}}` (Angular
///    templates) and `^\(\s*\)\s+{` (Shellshock) are fine there and rejected
///    here. Braces inside a character class are already literal in both.
///
/// 2. **`\<` and `\>` inside a character class.** PCRE tolerates a needless
///    backslash on any punctuation; `regex` accepts every one of them EXCEPT
///    these two. That is the whole of 921200's failure — determined by probing
///    the crate rather than guessed.
///
/// Applied only to a pattern that has ALREADY failed to compile, so it cannot
/// alter the behaviour of a rule that works.
fn pcre_compat(pattern: &str) -> String {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len() + 8);
    let mut i = 0;
    let mut in_class = false;
    // A `]` in the first position of a class is a literal `]`, not the close.
    let mut class_start = 0usize;

    while i < chars.len() {
        let c = chars[i];

        // An escape always consumes two characters, so it cannot be mistaken
        // for a class delimiter or a quantifier brace.
        if c == '\\' && i + 1 < chars.len() {
            let next = chars[i + 1];
            if in_class && (next == '<' || next == '>') {
                out.push(next); // drop the backslash `regex` refuses
            } else {
                out.push('\\');
                out.push(next);
            }
            i += 2;
            continue;
        }

        match c {
            '[' if !in_class => {
                in_class = true;
                class_start = i;
                out.push(c);
            }
            ']' if in_class => {
                // `[]]` and `[^]]`: a `]` here is content, not the terminator.
                let first = i == class_start + 1
                    || (i == class_start + 2 && chars.get(class_start + 1) == Some(&'^'));
                if !first {
                    in_class = false;
                }
                out.push(c);
            }
            '{' if !in_class && !starts_quantifier(&chars, i) => {
                out.push_str("\\{");
            }
            // A stray `}` needs no escaping — `regex` already reads it as a
            // literal — so it is left exactly as written.
            _ => out.push(c),
        }
        i += 1;
    }
    out
}

/// Whether the `{` at `i` opens a valid repetition: `{n}`, `{n,}` or `{n,m}`.
///
/// Anything else — `{`, `{{`, `{,3}`, `{.*}` — is a literal brace to PCRE.
fn starts_quantifier(chars: &[char], i: usize) -> bool {
    let mut j = i + 1;
    let digits_start = j;
    while j < chars.len() && chars[j].is_ascii_digit() {
        j += 1;
    }
    if j == digits_start {
        return false; // `{` must be followed by at least one digit
    }
    if chars.get(j) == Some(&',') {
        j += 1;
        while j < chars.len() && chars[j].is_ascii_digit() {
            j += 1;
        }
    }
    chars.get(j) == Some(&'}')
}

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
        let re = match Regex::new(pattern) {
            Ok(re) => re,
            Err(_) => {
                // The pattern is PCRE, written for ModSecurity. A handful of
                // constructs PCRE accepts are hard errors here — see
                // `pcre_compat`. Repair is attempted ONLY after a genuine
                // failure, so a pattern that already compiles is used exactly
                // as written and this can never change a working rule.
                let repaired = pcre_compat(pattern);
                if let Some(idx) = self.patterns.iter().position(|r| r.as_str() == repaired) {
                    return Ok(idx);
                }
                Regex::new(&repaired).with_context(|| format!("invalid regex: {pattern}"))?
            }
        };
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
                        //
                        // CHAIN CONDITIONS COUNT. Chain links are ANDed, so a
                        // single `Never` anywhere in the chain makes the whole
                        // rule unable to fire, exactly as a `Never` at the top
                        // level would. Testing only `rule.operator` was why this
                        // report read "zero coverage gap" while CRS 920220,
                        // 920221, 920240 and 920250 could not fire: every one of
                        // them carries its unsupported operator in a chain CHILD.
                        // The only trace was one importer WARN naming the operator
                        // but not the rule, and that WARN was invisible for months
                        // behind a RUST_LOG filter that excluded the crate.
                        let never_in_chain = rule
                            .chain_conditions
                            .iter()
                            .any(|c| matches!(c.operator, Operator::Never));
                        // A TARGET-LESS condition is inert for a different
                        // reason and used to be invisible. The importer drops
                        // target tokens it does not understand; when that empties
                        // a condition's list the emitter falls back to a constant
                        // false, and the rule is then counted in the inventory,
                        // listed in the console, and incapable of firing.
                        //
                        // It cost eight shipped rules — 932200, 932206, 932240,
                        // 933120, 933151, 941310, 942440, 944120 — all chain
                        // children reading MATCHED_VARS. Chain links are ANDed, so
                        // a constant-false child disables the parent, and several
                        // of those children are NEGATED refinements, meaning the
                        // effect was to switch the detection OFF rather than
                        // narrow it. The census reported "zero gap" throughout.
                        //
                        // Operators that need no target (rate limits, the
                        // unsupported-operator path) return before the emitter's
                        // target check, so they must not be counted here.
                        let needs_targets = |op: &Operator| {
                            !matches!(op, Operator::Never | Operator::RateLimit { .. })
                        };
                        let targetless = (rule.targets.is_empty() && needs_targets(&rule.operator))
                            || rule
                                .chain_conditions
                                .iter()
                                .any(|c| c.targets.is_empty() && needs_targets(&c.operator));

                        if matches!(rule.operator, Operator::Never) || never_in_chain || targetless
                        {
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

    let memo_uses = phase_programs
        .each_ref()
        .map(|program| vm::memo_uses(program));
    Ok(CompiledRuleSet {
        phase_programs,
        memo_uses,
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
    let chained = !rule.chain_conditions.is_empty();
    let meta = RuleMeta {
        id: rule.id,
        message: rule.message.clone().unwrap_or_default(),
        severity: rule.severity.unwrap_or(RuleSeverity::Notice),
        score_delta: rule.score_delta.unwrap_or(0),
        action: rule.action.clone(),
        tags: rule.tags.clone(),
        phase: rule.phase,
        skip_after: rule.skip_after.clone(),
        // A chain runs its setvars link by link (below), so none are left
        // for RuleEnd: running the starter's again there would count a
        // category score twice.
        setvars: if chained {
            Vec::new()
        } else {
            rule.setvars.clone()
        },
    };

    if !chained {
        emit_condition(
            &rule.targets,
            &rule.exclusions,
            &rule.operator,
            &rule.transforms,
            rule.multi_match,
            state,
            &mut instrs,
        )?;
        instrs.push(Instruction::RuleEnd { rule_id: rule.id });
        return Ok((instrs, meta));
    }

    // A chain, link by link, as ModSecurity runs it: each link is matched
    // with its OWN transformations, its setvars run as soon as it matches —
    // so the starter's `setvar:tx.content_type=|%{tx.0}|` exists before the
    // child reads `TX:content_type` — and the first link that does not match
    // ends the chain. Compiling every link up front and ANDing the results
    // ran the starter's setvars only after the child had already been
    // evaluated against a variable that did not exist yet, and applied the
    // starter's transformations to every child.
    let mut links: Vec<usize> = Vec::with_capacity(rule.chain_conditions.len() + 1);
    emit_link(
        &rule.targets,
        &rule.exclusions,
        &rule.operator,
        &rule.transforms,
        rule.multi_match,
        &rule.setvars,
        state,
        &mut instrs,
    )?;
    links.push(instrs.len());
    instrs.push(Instruction::ChainLink {
        setvars: rule.setvars.clone(),
        to_end: 0,
        last: false,
    });
    for (i, chain) in rule.chain_conditions.iter().enumerate() {
        emit_link(
            &chain.targets,
            &[],
            &chain.operator,
            &chain.transforms,
            chain.multi_match,
            &chain.setvars,
            state,
            &mut instrs,
        )?;
        links.push(instrs.len());
        instrs.push(Instruction::ChainLink {
            setvars: chain.setvars.clone(),
            to_end: 0,
            last: i + 1 == rule.chain_conditions.len(),
        });
    }
    // Each ChainLink jumps onto the RuleEnd that follows the last link.
    let end = instrs.len();
    for at in links {
        if let Instruction::ChainLink { to_end, .. } = &mut instrs[at] {
            *to_end = u32::try_from(end - at).context("chain too long to jump over")?;
        }
    }
    instrs.push(Instruction::RuleEnd { rule_id: rule.id });

    Ok((instrs, meta))
}

/// One link of a chain: its condition, with every regex match recording all
/// of its matches when one of the link's setvars is named from the match
/// (`tx.header_name_920450_%{tx.0}`) and so runs once per matched value.
#[allow(clippy::too_many_arguments)]
fn emit_link(
    targets: &[TargetExpr],
    exclusions: &[TargetExclusion],
    operator: &Operator,
    transforms: &[Transform],
    multi_match: bool,
    setvars: &[SetVar],
    state: &mut CompilerState,
    instrs: &mut Vec<Instruction>,
) -> Result<()> {
    let from = instrs.len();
    emit_condition(
        targets,
        exclusions,
        operator,
        transforms,
        multi_match,
        state,
        instrs,
    )?;
    if setvars.iter().any(|sv| sv.name.contains("%{")) {
        for instr in &mut instrs[from..] {
            if let Instruction::MatchRx { pattern_id } = *instr {
                *instr = Instruction::MatchRxAll { pattern_id };
            }
        }
    }
    Ok(())
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

    emit_condition(
        &vp.targets,
        &[],
        &vp.operator,
        &[],
        false,
        state,
        &mut instrs,
    )?;
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
    exclusions: &[TargetExclusion],
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
        let spec = TargetSpec::from(&tex.target).excluding(exclusions);
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
        Operator::ValidateByteRange(ranges) => {
            instrs.push(Instruction::ValidateByteRange {
                ranges: ranges.clone(),
            });
        }
        Operator::ValidateUrlEncoding => {
            instrs.push(Instruction::ValidateUrlEncoding);
        }
        Operator::ValidateUtf8Encoding => {
            instrs.push(Instruction::ValidateUtf8Encoding);
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
