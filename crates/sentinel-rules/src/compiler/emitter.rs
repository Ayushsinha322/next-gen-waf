use std::collections::HashMap;

use aho_corasick::AhoCorasick;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::dsl::ast::{RuleAction, RulePhase, RuleSeverity, Target, Transform};

// ---------------------------------------------------------------------------
// Target specification stored in instructions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TargetSpec {
    Args,
    ArgsNames,
    RequestBody,
    RequestUri,
    RequestFilename,
    RequestMethod,
    RequestLine,
    RequestHeadersAll,
    RequestHeader(String),
    RequestCookiesAll,
    RequestCookie(String),
    ResponseHeadersAll,
    ResponseHeader(String),
    ResponseBody,
    Files,
    FilesNames,
    FilesCombinedSize,
    RemoteAddr,
    Geo,
    TxVar(String),
    CountOf(Box<TargetSpec>),
}

impl From<&Target> for TargetSpec {
    fn from(t: &Target) -> Self {
        match t {
            Target::Args => TargetSpec::Args,
            Target::ArgsNames => TargetSpec::ArgsNames,
            Target::RequestBody => TargetSpec::RequestBody,
            Target::RequestUri => TargetSpec::RequestUri,
            Target::RequestFilename => TargetSpec::RequestFilename,
            Target::RequestMethod => TargetSpec::RequestMethod,
            Target::RequestLine => TargetSpec::RequestLine,
            Target::RequestHeaders(None) => TargetSpec::RequestHeadersAll,
            Target::RequestHeaders(Some(h)) => TargetSpec::RequestHeader(h.clone()),
            Target::RequestCookies(None) => TargetSpec::RequestCookiesAll,
            Target::RequestCookies(Some(c)) => TargetSpec::RequestCookie(c.clone()),
            Target::ResponseHeaders(None) => TargetSpec::ResponseHeadersAll,
            Target::ResponseHeaders(Some(h)) => TargetSpec::ResponseHeader(h.clone()),
            Target::ResponseBody => TargetSpec::ResponseBody,
            Target::Files => TargetSpec::Files,
            Target::FilesNames => TargetSpec::FilesNames,
            Target::FilesCombinedSize => TargetSpec::FilesCombinedSize,
            Target::RemoteAddr => TargetSpec::RemoteAddr,
            Target::Geo => TargetSpec::Geo,
            Target::TxVar(v) => TargetSpec::TxVar(v.clone()),
            Target::CountOf(inner) => {
                TargetSpec::CountOf(Box::new(TargetSpec::from(inner.as_ref())))
            }
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
    MatchRx {
        pattern_id: usize,
    },

    /// Pop `StrVec`, apply Aho-Corasick set `ac_sets[set_id]`, push `Bool(any_match)`.
    MatchMulti {
        set_id: usize,
    },

    /// Pop `StrVec`, check any == `literals[literal_id]`, push `Bool`.
    MatchEq {
        literal_id: usize,
    },

    /// Pop `StrVec`, push `Bool(!values.is_empty() && values.iter().any(|s| !s.is_empty()))`.
    Exists,

    /// Pop `StrVec`, run libinjection SQLi detection on each value, push
    /// `Bool(any value flagged as SQL injection)`.
    DetectSqli,

    /// Pop `StrVec`, run libinjection XSS detection on each value, push
    /// `Bool(any value flagged as XSS)`.
    DetectXss,
    /// Pop `StrVec`, push `Bool(any value is an off-domain URL)`.
    DetectOffDomainUrl,

    /// Always push `Bool(false)` — used for intentionally disabled rules.
    Never,

    /// Push the current anomaly score as `Int`.
    LoadAnomalyScore,

    /// Pop `Int` or `Float`, compare >= threshold, push `Bool`.
    /// Threshold is stored as f64 so it works for both anomaly scores and ML probabilities.
    CmpGe {
        threshold: f64,
    },

    /// Push the ML score for model `ml_models[model_id]` as `Float`.
    MlScore {
        model_id: usize,
    },

    /// Push a `Bool` for whether the rate limit `window_id` is exceeded (host call).
    RateCheck {
        window_id: usize,
    },

    // --- Boolean combinators ---
    And,
    Or,
    Not,

    /// Pop `StrVec`, apply each transform in order, push transformed `StrVec`.
    /// When `multi_match` is `true`, also push results after each intermediate
    /// transform prefix so the subsequent operator can match at any step.
    ApplyTransforms {
        transforms: Vec<Transform>,
        multi_match: bool,
    },

    /// Jump `offset` instructions forward if stack top is Bool(false).
    /// Does NOT pop the stack.
    JmpIfFalse {
        offset: i32,
    },

    /// Pop Bool from stack.  If true, apply the rule's action/score/log.
    /// The rule metadata is looked up by `rule_id` in `CompiledRuleSet::rule_meta`.
    RuleEnd {
        rule_id: u32,
    },

    /// Named label emitted for each `SecMarker` directive.
    /// Acts as a no-op at runtime; `skipAfter` rules jump to the first
    /// `Marker` whose name matches their `skip_after` field.
    Marker(String),
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
    /// CRS `skipAfter:MARKER` — if this rule fires, the VM jumps forward
    /// to the `Marker` instruction with this name, skipping all rules in between.
    pub skip_after: Option<String>,
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
            skip_after: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Compiled rule set
// ---------------------------------------------------------------------------

/// Which rules from the source ruleset are NOT actually enforced, so operators
/// can see coverage gaps instead of them vanishing into a log line. Populated
/// by the compiler and surfaced at load time.
#[derive(Debug, Clone, Default)]
pub struct RuleCoverage {
    /// Rules that failed to compile (e.g. an unsupported PCRE regex) and are
    /// therefore not loaded at all: `(rule_id, reason)`.
    pub dropped: Vec<(u32, String)>,
    /// Rules that loaded but are permanently inert because their operator is
    /// unsupported (imported as `Never`) — they can never match.
    pub disabled: Vec<u32>,
}

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

    /// Rules from the source set that are not enforced (compile-dropped or
    /// disabled). Empty when every rule compiled and is active.
    pub coverage: RuleCoverage,
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
            coverage: RuleCoverage::default(),
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
