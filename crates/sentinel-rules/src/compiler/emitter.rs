use std::collections::HashMap;

use aho_corasick::AhoCorasick;
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::vm::MemoKey;
use crate::dsl::ast::{
    ExclusionKey, InterpCmp, RuleAction, RulePhase, RuleSeverity, SetVar, Target, TargetExclusion,
    Transform,
};

// ---------------------------------------------------------------------------
// Target specification stored in instructions
// ---------------------------------------------------------------------------

/// What a `LoadTarget` reads. `Eq + Hash` because the VM memoizes the values of
/// request-derived targets for the rest of one `evaluate` call.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetSpec {
    Args,
    ArgsNames,
    RequestBody,
    RequestUri,
    RequestFilename,
    RequestBasename,
    RequestMethod,
    RequestLine,
    RequestProtocol,
    ReqbodyProcessor,
    RequestHeadersAll,
    RequestHeader(String),
    RequestCookiesAll,
    RequestCookie(String),
    RequestCookiesNames,
    RequestHeadersNames,
    ArgsGet,
    ArgsGetNames,
    QueryString,
    ResponseHeadersAll,
    ResponseHeader(String),
    ResponseBody,
    Files,
    FilesNames,
    FilesCombinedSize,
    ArgsCombinedSize,
    MultipartPartHeadersAll,
    MultipartPartHeader(String),
    RemoteAddr,
    Geo,
    TxVar(String),
    /// The value the PREVIOUS condition in this chain matched — CRS
    /// `MATCHED_VAR` / `MATCHED_VARS`.
    ///
    /// Resolved from the VM's per-rule `last_matched`, not from the request, so
    /// it is only meaningful inside a chain. Outside one it is empty, which is
    /// the correct reading: nothing has matched yet.
    ///
    /// It exists because dropping the target made the condition target-less,
    /// which compiles to a constant false and silently disabled eight shipped
    /// rules. Several of them are NEGATED refinements ("...and the matched text
    /// is not a JWT"), so losing the child did not make the parent stricter, it
    /// turned the parent off.
    ///
    /// The previous link's WHOLE value, as ModSecurity gives it — the last
    /// value that link matched — not the text its pattern found: 944120's
    /// parent finds `clonetransformer` and its child looks for `processbuilder`
    /// elsewhere in the same value.
    MatchedVar,
    /// `MATCHED_VARS`: every value the previous link matched.
    MatchedVars,
    /// `ARGS:name` (query then body) or `ARGS_GET:name` (query only).
    ArgNamed {
        name: String,
        get_only: bool,
    },
    CountOf(Box<TargetSpec>),
    /// `base` without the members `keys` name: a collection target its rule
    /// has exclusions for (`REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/`).
    Except {
        base: Box<TargetSpec>,
        keys: Vec<ExclusionKey>,
    },
}

impl TargetSpec {
    /// This target with the `exclusions` that name its collection applied —
    /// wrapped in `Except` — or unchanged when none does. Only the keyed
    /// collections have members to leave out.
    pub fn excluding(self, exclusions: &[TargetExclusion]) -> TargetSpec {
        let collection = match &self {
            TargetSpec::Args => "ARGS",
            TargetSpec::ArgsNames => "ARGS_NAMES",
            TargetSpec::ArgsGet => "ARGS_GET",
            TargetSpec::ArgsGetNames => "ARGS_GET_NAMES",
            TargetSpec::RequestCookiesAll => "REQUEST_COOKIES",
            TargetSpec::RequestCookiesNames => "REQUEST_COOKIES_NAMES",
            TargetSpec::RequestHeadersAll => "REQUEST_HEADERS",
            TargetSpec::RequestHeadersNames => "REQUEST_HEADERS_NAMES",
            _ => return self,
        };
        let mut keys: Vec<ExclusionKey> = exclusions
            .iter()
            .filter(|e| e.collection == collection)
            .map(|e| e.key.clone())
            .collect();
        if keys.is_empty() {
            return self;
        }
        // One memo entry for every rule with the same exclusions, whatever
        // order they were written in.
        keys.sort();
        keys.dedup();
        TargetSpec::Except {
            base: Box::new(self),
            keys,
        }
    }

    /// ModSecurity-style label for this target, e.g. `ARGS`,
    /// `REQUEST_HEADERS:User-Agent`.
    ///
    /// Used to record WHICH part of a request tripped a rule, so a security event
    /// can name the parameter to exclude instead of leaving an operator to guess.
    pub fn label(&self) -> String {
        match self {
            TargetSpec::Except { base, .. } => base.label(),
            TargetSpec::Args => "ARGS".into(),
            TargetSpec::ArgsNames => "ARGS_NAMES".into(),
            TargetSpec::RequestBody => "REQUEST_BODY".into(),
            TargetSpec::RequestUri => "REQUEST_URI".into(),
            TargetSpec::RequestFilename => "REQUEST_FILENAME".into(),
            TargetSpec::RequestBasename => "REQUEST_BASENAME".into(),
            TargetSpec::RequestMethod => "REQUEST_METHOD".into(),
            TargetSpec::RequestProtocol => "REQUEST_PROTOCOL".into(),
            TargetSpec::ReqbodyProcessor => "REQBODY_PROCESSOR".into(),
            TargetSpec::RequestLine => "REQUEST_LINE".into(),
            TargetSpec::RequestHeadersAll => "REQUEST_HEADERS".into(),
            TargetSpec::RequestHeader(h) => format!("REQUEST_HEADERS:{h}"),
            TargetSpec::RequestCookiesAll => "REQUEST_COOKIES".into(),
            TargetSpec::RequestCookiesNames => "REQUEST_COOKIES_NAMES".into(),
            TargetSpec::RequestHeadersNames => "REQUEST_HEADERS_NAMES".into(),
            TargetSpec::ArgsGet => "ARGS_GET".into(),
            TargetSpec::ArgsGetNames => "ARGS_GET_NAMES".into(),
            TargetSpec::QueryString => "QUERY_STRING".into(),
            TargetSpec::RequestCookie(c) => format!("REQUEST_COOKIES:{c}"),
            TargetSpec::ArgNamed { name, get_only } => {
                format!("{}:{name}", if *get_only { "ARGS_GET" } else { "ARGS" })
            }
            TargetSpec::ResponseHeadersAll => "RESPONSE_HEADERS".into(),
            TargetSpec::ResponseHeader(h) => format!("RESPONSE_HEADERS:{h}"),
            TargetSpec::ResponseBody => "RESPONSE_BODY".into(),
            TargetSpec::Files => "FILES".into(),
            TargetSpec::FilesNames => "FILES_NAMES".into(),
            TargetSpec::FilesCombinedSize => "FILES_COMBINED_SIZE".into(),
            TargetSpec::ArgsCombinedSize => "ARGS_COMBINED_SIZE".into(),
            TargetSpec::MultipartPartHeadersAll => "MULTIPART_PART_HEADERS".into(),
            TargetSpec::MultipartPartHeader(p) => format!("MULTIPART_PART_HEADERS:{p}"),
            TargetSpec::RemoteAddr => "REMOTE_ADDR".into(),
            TargetSpec::Geo => "GEO".into(),
            TargetSpec::TxVar(v) => format!("TX:{v}"),
            TargetSpec::MatchedVar => "MATCHED_VAR".into(),
            TargetSpec::MatchedVars => "MATCHED_VARS".into(),
            TargetSpec::CountOf(inner) => format!("&{}", inner.label()),
        }
    }
}

impl From<&Target> for TargetSpec {
    fn from(t: &Target) -> Self {
        match t {
            Target::Args => TargetSpec::Args,
            Target::ArgsNames => TargetSpec::ArgsNames,
            Target::RequestCookiesNames => TargetSpec::RequestCookiesNames,
            Target::RequestHeadersNames => TargetSpec::RequestHeadersNames,
            Target::ArgsGet => TargetSpec::ArgsGet,
            Target::ArgsGetNames => TargetSpec::ArgsGetNames,
            Target::QueryString => TargetSpec::QueryString,
            Target::RequestBody => TargetSpec::RequestBody,
            Target::RequestUri => TargetSpec::RequestUri,
            Target::RequestFilename => TargetSpec::RequestFilename,
            Target::RequestBasename => TargetSpec::RequestBasename,
            Target::RequestMethod => TargetSpec::RequestMethod,
            Target::RequestProtocol => TargetSpec::RequestProtocol,
            Target::ReqbodyProcessor => TargetSpec::ReqbodyProcessor,
            Target::RequestLine => TargetSpec::RequestLine,
            Target::RequestHeaders(None) => TargetSpec::RequestHeadersAll,
            Target::RequestHeaders(Some(h)) => TargetSpec::RequestHeader(h.clone()),
            Target::RequestCookies(None) => TargetSpec::RequestCookiesAll,
            Target::RequestCookies(Some(c)) => TargetSpec::RequestCookie(c.clone()),
            Target::ArgNamed { name, get_only } => TargetSpec::ArgNamed {
                name: name.clone(),
                get_only: *get_only,
            },
            Target::ResponseHeaders(None) => TargetSpec::ResponseHeadersAll,
            Target::ResponseHeaders(Some(h)) => TargetSpec::ResponseHeader(h.clone()),
            Target::ResponseBody => TargetSpec::ResponseBody,
            Target::Files => TargetSpec::Files,
            Target::FilesNames => TargetSpec::FilesNames,
            Target::FilesCombinedSize => TargetSpec::FilesCombinedSize,
            Target::ArgsCombinedSize => TargetSpec::ArgsCombinedSize,
            Target::MultipartPartHeaders(None) => TargetSpec::MultipartPartHeadersAll,
            Target::MultipartPartHeaders(Some(p)) => TargetSpec::MultipartPartHeader(p.clone()),
            Target::RemoteAddr => TargetSpec::RemoteAddr,
            Target::Geo => TargetSpec::Geo,
            Target::TxVar(v) => TargetSpec::TxVar(v.clone()),
            Target::MatchedVar => TargetSpec::MatchedVar,
            Target::MatchedVars => TargetSpec::MatchedVars,
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
    ///
    /// `negate` is `!@rx`, judged per value as ModSecurity does: true when ANY
    /// value does not match. Negating the combined result instead asked
    /// whether NO value matched, so on a multi-valued target (FILES_NAMES,
    /// MATCHED_VARS, `TX:/regex/`) one value that matched hid every one that
    /// did not.
    MatchRx {
        pattern_id: usize,
        #[serde(default)]
        negate: bool,
    },

    /// [`Instruction::MatchRx`] that tests EVERY value instead of stopping at the
    /// first match, and records each match — its capture groups and the whole
    /// value — for the [`Instruction::ChainLink`] that follows. Emitted only
    /// for a chain link whose matches the chain goes on to use: a `setvar`
    /// whose name is built from the match (CRS's `tx.header_name_920450_%{tx.0}`,
    /// which ModSecurity runs once per matched value), or a next link that
    /// reads `MATCHED_VAR(S)`.
    MatchRxAll {
        pattern_id: usize,
        #[serde(default)]
        negate: bool,
    },

    /// [`Instruction::MatchMulti`] that tests every value and records each
    /// matching one, for a next link that reads `MATCHED_VAR(S)` (CRS 933120's
    /// `@pmFromFile` parent).
    MatchMultiAll {
        set_id: usize,
    },

    /// Pop `StrVec`, expand the `%{...}` macros in `literals[raw_id]` against the
    /// request, then compare each value with `cmp`.
    ///
    /// Pushes `Absent` — never `Bool(false)` — when a macro cannot be resolved, so
    /// that a negated form such as `!@within %{tx.allowed_methods}` degrades to
    /// "did not fire" rather than "deny everything".
    MatchInterpolated {
        cmp: InterpCmp,
        raw_id: usize,
        /// Per value, as `MatchRx`'s: CRS 931130's `!@endsWith .%{request_headers.host}`
        /// over every `TX:/rfi_parameter_.*/` it set.
        #[serde(default)]
        negate: bool,
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
    /// Pop `StrVec`, push `Bool(any value contains an SSRF URL)`.
    DetectSsrfUrl,
    /// Pop `StrVec`, push `Bool(any value is an IP inside one of these CIDRs)`.
    IpMatch {
        cidrs: Vec<String>,
    },

    /// Pop `StrVec`, push `Bool(any value has a byte OUTSIDE these ranges)`.
    /// Inclusive ranges, as `@validateByteRange` gives them.
    ValidateByteRange {
        ranges: Vec<(u8, u8)>,
    },

    /// Pop `StrVec`, push `Bool(any value contains malformed percent-encoding)`.
    /// `@validateUrlEncoding`.
    ValidateUrlEncoding,

    /// Pop `StrVec`, push `Bool(any value's percent-escapes decode to invalid
    /// UTF-8)`. `@validateUtf8Encoding`.
    ValidateUtf8Encoding,

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

    /// Close one link of a chained rule, the way ModSecurity runs a chain.
    ///
    /// Pops the link's result. If it matched, the link's own `setvar`s run now
    /// — before the next link is evaluated, which is what lets a CRS parent
    /// store a value for its child to check — and evaluation continues with the
    /// next link; the LAST link pushes `Bool(true)` for `RuleEnd`. If it did not
    /// match, `Bool(false)` is pushed and the VM jumps `to_end` instructions
    /// forward, onto the rule's `RuleEnd`: no later link is evaluated and none
    /// of its `setvar`s run.
    ChainLink {
        setvars: Vec<SetVar>,
        to_end: u32,
        last: bool,
    },

    /// Opens a rule that another rule's `ctl:ruleRemoveTargetById` may take a
    /// target off. Emitted only for such rules (942440, for CRS 942441/942442):
    /// the VM applies the removals the request has collected for this rule to
    /// every target the rule loads, until its RuleEnd.
    RuleStart {
        rule_id: u32,
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
    /// `setvar` mutations applied to the per-request TX store when this rule
    /// fires (executed by the VM in `fire_rule`).
    #[serde(default)]
    pub setvars: Vec<SetVar>,
    /// `ctl:ruleRemoveTargetById` this rule applies to the request when it fires.
    #[serde(default)]
    pub remove_targets: Vec<(u32, String)>,
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
            setvars: Vec::new(),
            remove_targets: Vec::new(),
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
#[derive(Default)]
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

    /// How many rules of each phase program read each memoizable target and
    /// (target, transform chain) pair; see `vm::memo_uses`. The VM keeps a
    /// collection for the rest of a call only when several rules read it, and
    /// spends its memory budget on the most-read ones first. Derived from
    /// `phase_programs` at compile time.
    pub(crate) memo_uses: [HashMap<MemoKey, u32>; 7],
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
