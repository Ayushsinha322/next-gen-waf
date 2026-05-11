use std::collections::HashMap;

use aho_corasick::AhoCorasick;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::dsl::ast::{RuleAction, RulePhase, RuleSeverity, Target};

// ---------------------------------------------------------------------------
// Target specification stored in instructions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetSpec {
    Args,
    ArgsNames,
    RequestBody,
    RequestUri,
    RequestLine,
    RequestHeadersAll,
    RequestHeader(String),
    RequestCookiesAll,
    RequestCookie(String),
    ResponseHeadersAll,
    ResponseHeader(String),
    ResponseBody,
    RemoteAddr,
    Geo,
    TxVar(String),
}

impl From<&Target> for TargetSpec {
    fn from(t: &Target) -> Self {
        match t {
            Target::Args => TargetSpec::Args,
            Target::ArgsNames => TargetSpec::ArgsNames,
            Target::RequestBody => TargetSpec::RequestBody,
            Target::RequestUri => TargetSpec::RequestUri,
            Target::RequestLine => TargetSpec::RequestLine,
            Target::RequestHeaders(None) => TargetSpec::RequestHeadersAll,
            Target::RequestHeaders(Some(h)) => TargetSpec::RequestHeader(h.clone()),
            Target::RequestCookies(None) => TargetSpec::RequestCookiesAll,
            Target::RequestCookies(Some(c)) => TargetSpec::RequestCookie(c.clone()),
            Target::ResponseHeaders(None) => TargetSpec::ResponseHeadersAll,
            Target::ResponseHeaders(Some(h)) => TargetSpec::ResponseHeader(h.clone()),
            Target::ResponseBody => TargetSpec::ResponseBody,
            Target::RemoteAddr => TargetSpec::RemoteAddr,
            Target::Geo => TargetSpec::Geo,
            Target::TxVar(v) => TargetSpec::TxVar(v.clone()),
        }
    }
}

// ---------------------------------------------------------------------------
// VM Instruction set
// ---------------------------------------------------------------------------

/// A single SRL-VM instruction.
///
/// Instructions form a flat per-phase program.  Stack is `Vec<StackVal>`.
/// Each rule compiles to a sequence terminated by `RuleEnd`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Instruction {
    /// Push all values for this target as `StrVec` onto the stack.
    LoadTarget(TargetSpec),

    /// Pop `StrVec`, apply regex `patterns[pattern_id]`, push `Bool(any_match)`.
    MatchRx { pattern_id: usize },

    /// Pop `StrVec`, apply Aho-Corasick set `ac_sets[set_id]`, push `Bool(any_match)`.
    MatchMulti { set_id: usize },

    /// Pop `StrVec`, check any == `literals[literal_id]`, push `Bool`.
    MatchEq { literal_id: usize },

    /// Pop `StrVec`, push `Bool(!values.is_empty() && values.iter().any(|s| !s.is_empty()))`.
    Exists,

    /// Push the current anomaly score as `Int`.
    LoadAnomalyScore,

    /// Pop `Int` or `Float`, compare >= threshold, push `Bool`.
    /// Threshold is stored as f64 so it works for both anomaly scores and ML probabilities.
    CmpGe { threshold: f64 },

    /// Push the ML score for model `ml_models[model_id]` as `Float`.
    MlScore { model_id: usize },

    /// Push a `Bool` for whether the rate limit `window_id` is exceeded (host call).
    RateCheck { window_id: usize },

    // --- Boolean combinators ---
    And,
    Or,
    Not,

    /// Jump `offset` instructions forward if stack top is Bool(false).
    /// Does NOT pop the stack.
    JmpIfFalse { offset: i32 },

    /// Pop Bool from stack.  If true, apply the rule's action/score/log.
    /// The rule metadata is looked up by `rule_id` in `CompiledRuleSet::rule_meta`.
    RuleEnd { rule_id: u32 },
}

// ---------------------------------------------------------------------------
// Rule metadata (looked up by RuleEnd)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMeta {
    pub id: u32,
    pub message: String,
    pub severity: RuleSeverity,
    pub score_delta: i32,
    pub action: RuleAction,
    pub tags: Vec<String>,
    pub phase: RulePhase,
}

impl Default for RuleMeta {
    fn default() -> Self {
        Self {
            id: 0,
            message: String::new(),
            severity: RuleSeverity::Notice,
            score_delta: 0,
            action: RuleAction::Log,
            tags: Vec::new(),
            phase: RulePhase::RequestBody,
        }
    }
}

// ---------------------------------------------------------------------------
// Compiled rule set
// ---------------------------------------------------------------------------

/// The output of the compiler — shared across all request-processing threads
/// via `Arc`.  All fields are immutable after compilation.
pub struct CompiledRuleSet {
    /// Instruction sequences, indexed by `RulePhase as usize` (0-6).
    pub phase_programs: [Vec<Instruction>; 7],

    /// Compiled regex patterns indexed by `pattern_id`.
    pub patterns: Vec<Regex>,

    /// Aho-Corasick automata indexed by `set_id`.
    pub ac_sets: Vec<AhoCorasick>,

    /// String literals indexed by `literal_id` (for MatchEq).
    pub literals: Vec<String>,

    /// ML model names indexed by `model_id`.
    pub ml_models: Vec<String>,

    /// Plugin names indexed by `plugin_id`.
    pub plugin_names: Vec<String>,

    /// Rule metadata keyed by `rule_id`.
    pub rule_meta: HashMap<u32, RuleMeta>,
}

impl Default for CompiledRuleSet {
    fn default() -> Self {
        Self {
            phase_programs: Default::default(),
            patterns: Vec::new(),
            ac_sets: Vec::new(),
            literals: Vec::new(),
            ml_models: Vec::new(),
            plugin_names: Vec::new(),
            rule_meta: HashMap::new(),
        }
    }
}

impl std::fmt::Debug for CompiledRuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledRuleSet")
            .field("rules", &self.rule_meta.len())
            .field("patterns", &self.patterns.len())
            .field("ac_sets", &self.ac_sets.len())
            .finish()
    }
}
