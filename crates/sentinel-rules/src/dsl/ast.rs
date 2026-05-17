use serde::{Deserialize, Serialize};

pub type RuleId = u32;

// ---------------------------------------------------------------------------
// Top-level file
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleFile {
    pub items: Vec<RuleItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleItem {
    Directive(Directive),
    Rule(RuleDef),
    VirtualPatch(VirtualPatch),
}

// ---------------------------------------------------------------------------
// Rule definition
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDef {
    pub id: RuleId,
    pub phase: RulePhase,
    pub targets: Vec<TargetExpr>,
    pub operator: Operator,
    pub score_delta: Option<i32>,
    pub severity: Option<RuleSeverity>,
    pub message: Option<String>,
    pub action: RuleAction,
    pub tags: Vec<String>,
    /// Additional conditions joined with AND (from CRS `chain` directive).
    /// All chain conditions must match for the rule to fire.
    #[serde(default)]
    pub chain_conditions: Vec<ChainCondition>,
    /// Transformations applied to target values before operator matching.
    #[serde(default)]
    pub transforms: Vec<Transform>,
    /// CRS `skipAfter:MARKER` — if this rule fires, skip to the named SecMarker.
    #[serde(default)]
    pub skip_after: Option<String>,
}

/// A single chained condition from a CRS `chain` SecRule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainCondition {
    pub targets: Vec<TargetExpr>,
    pub operator: Operator,
}

impl Default for RuleDef {
    fn default() -> Self {
        Self {
            id: 0,
            phase: RulePhase::RequestBody,
            targets: Vec::new(),
            operator: Operator::Exists,
            score_delta: None,
            severity: None,
            message: None,
            action: RuleAction::Log,
            tags: Vec::new(),
            chain_conditions: Vec::new(),
            transforms: Vec::new(),
            skip_after: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Virtual patch
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualPatch {
    pub cve: String,
    pub phase: RulePhase,
    pub targets: Vec<TargetExpr>,
    pub operator: Operator,
    pub action: RuleAction,
    pub message: Option<String>,
    pub expires: Option<String>,
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

/// A target in an expression, optionally followed by a combinator for the
/// next target (i.e. `ARGS | REQUEST_BODY` becomes
/// `[TargetExpr{target:Args, combinator:Some(Or)}, TargetExpr{target:RequestBody, combinator:None}]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetExpr {
    pub target: Target,
    /// Combinator that joins this target to the *next* one in the list.
    pub combinator: Option<TargetCombinator>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetCombinator {
    Or,
    And,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    Args,
    ArgsNames,
    RequestHeaders(Option<String>),
    RequestBody,
    RequestUri,
    RequestLine,
    RequestCookies(Option<String>),
    ResponseHeaders(Option<String>),
    ResponseBody,
    RemoteAddr,
    Geo,
    TxVar(String),
    CountOf(Box<Target>),
}

// ---------------------------------------------------------------------------
// Transforms
// ---------------------------------------------------------------------------

/// Input transformations applied to target values before operator matching.
/// Applied in declaration order; `t:none` resets the list (handled by the importer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transform {
    Lowercase,
    UrlDecodeUni,
    RemoveNulls,
    ReplaceNulls,
    HtmlEntityDecode,
    RemoveWhitespace,
    CompressWhitespace,
    JsDecode,
    CssDecode,
}

// ---------------------------------------------------------------------------
// Operators
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operator {
    Rx(String),
    ContainsWord(Vec<String>),
    Eq(String),
    Ge(i64),
    Exists,
    AnomalyScore { op: CmpOp, threshold: u32 },
    MlScore { model: String, op: CmpOp, threshold: f32 },
    RateLimit { dimension: RateLimitDim, rps: u32, burst: u32 },
    Not(Box<Operator>),
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CmpOp {
    Ge,
    Gt,
    Le,
    Lt,
    Eq,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RateLimitDim {
    PerIp,
    PerSite,
    Global,
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    Score,
    Block,
    Allow,
    Log,
    Challenge(ChallengeMode),
    PluginCall { name: String, args: serde_json::Value },
    Redirect(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeMode {
    NativePow,
    Captcha,
}

// ---------------------------------------------------------------------------
// Phase + Severity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RulePhase {
    Connection      = 0,
    RequestHeaders  = 1,
    RequestBody     = 2,
    Upstream        = 3,
    ResponseHeaders = 4,
    ResponseBody    = 5,
    Logging         = 6,
}

impl RulePhase {
    pub fn as_index(self) -> usize {
        self as usize
    }

    /// Map a ModSecurity phase number (1-5) to a RulePhase.
    pub fn from_modsec(n: u8) -> Option<Self> {
        match n {
            1 => Some(Self::RequestHeaders),
            2 => Some(Self::RequestBody),
            3 => Some(Self::ResponseHeaders),
            4 => Some(Self::ResponseBody),
            5 => Some(Self::Logging),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleSeverity {
    Critical,
    High,
    Medium,
    Low,
    Notice,
}

// ---------------------------------------------------------------------------
// Directives
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Directive {
    RuleEngine(EngineMode),
    RequestBodyAccess(bool),
    ResponseBodyAccess(bool),
    DefaultAction(String),
    Include(String),
    SecRule(SecRuleDirective),
    SecAction(String),
    SecMarker(String),
    VarDecl { name: String, var_type: VarType, initial: String },
    Import(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineMode {
    On,
    Off,
    DetectionOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VarType {
    Score,
    Int,
    Str,
}

/// Raw parsed SecRule directive — further processed by the CRS importer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecRuleDirective {
    /// Raw targets string, e.g. `"ARGS|ARGS_NAMES"`.
    pub targets: String,
    /// Raw operator string, e.g. `"@rx (?i)select"`.
    pub operator: String,
    /// Raw actions string, e.g. `"id:942100,phase:2,block,msg:'SQLi'"`.
    pub actions: String,
}
