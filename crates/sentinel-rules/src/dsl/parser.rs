use nom::{
    IResult,
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_while, take_while1},
    character::complete::{char, digit1, multispace0, multispace1, space1},
    combinator::{map, map_res, opt, recognize, value},
    multi::{many0, separated_list0},
    sequence::{delimited, pair, preceded, terminated, tuple},
};

use super::ast::*;
use super::error::ParseError;

// ---------------------------------------------------------------------------
// Whitespace + comment helpers
// ---------------------------------------------------------------------------

/// Skip any whitespace (spaces, tabs, newlines) and `# ...` comments.
fn ws(input: &str) -> IResult<&str, ()> {
    let (input, _) = multispace0(input)?;
    // Consume zero or more comment lines
    let mut input = input;
    loop {
        if input.starts_with('#') {
            // skip to end of line
            let end = input.find('\n').map(|p| p + 1).unwrap_or(input.len());
            input = &input[end..];
            let (rest, _) = multispace0(input)?;
            input = rest;
        } else {
            break;
        }
    }
    Ok((input, ()))
}

/// Skip inline horizontal whitespace only (spaces/tabs, no newlines).
fn iws(input: &str) -> IResult<&str, ()> {
    let (input, _) = take_while(|c| c == ' ' || c == '\t')(input)?;
    Ok((input, ()))
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

fn identifier(input: &str) -> IResult<&str, &str> {
    recognize(pair(
        take_while1(|c: char| c.is_alphabetic() || c == '_'),
        take_while(|c: char| c.is_alphanumeric() || c == '_' || c == '-'),
    ))(input)
}

fn unsigned_int(input: &str) -> IResult<&str, u32> {
    map_res(digit1, |s: &str| s.parse::<u32>())(input)
}

fn signed_int(input: &str) -> IResult<&str, i32> {
    map_res(
        recognize(pair(opt(alt((char('+'), char('-')))), digit1)),
        |s: &str| s.parse::<i32>(),
    )(input)
}

/// Parse a double-quoted string, handling `\"` and `\\` escapes.
fn quoted_string(input: &str) -> IResult<&str, String> {
    let (input, _) = char('"')(input)?;
    let mut result = String::new();
    let mut remaining = input;
    loop {
        match remaining.find(|c| c == '"' || c == '\\') {
            None => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Char,
                )));
            }
            Some(pos) => {
                result.push_str(&remaining[..pos]);
                remaining = &remaining[pos..];
                if remaining.starts_with("\\\"") {
                    result.push('"');
                    remaining = &remaining[2..];
                } else if remaining.starts_with("\\\\") {
                    result.push('\\');
                    remaining = &remaining[2..];
                } else if remaining.starts_with("\\n") {
                    result.push('\n');
                    remaining = &remaining[2..];
                } else if remaining.starts_with('"') {
                    remaining = &remaining[1..];
                    break;
                } else {
                    // other escape: copy as-is
                    result.push_str(&remaining[..2]);
                    remaining = &remaining[2..];
                }
            }
        }
    }
    Ok((remaining, result))
}

/// Parse a single-quoted string (used in CRS action strings like `msg:'...'`).
pub fn single_quoted_string(input: &str) -> IResult<&str, String> {
    let (input, _) = char('\'')(input)?;
    let mut result = String::new();
    let mut remaining = input;
    loop {
        match remaining.find(|c| c == '\'' || c == '\\') {
            None => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Char,
                )));
            }
            Some(pos) => {
                result.push_str(&remaining[..pos]);
                remaining = &remaining[pos..];
                if remaining.starts_with("\\'") {
                    result.push('\'');
                    remaining = &remaining[2..];
                } else if remaining.starts_with("\\\\") {
                    result.push('\\');
                    remaining = &remaining[2..];
                } else if remaining.starts_with('\'') {
                    remaining = &remaining[1..];
                    break;
                } else {
                    result.push_str(&remaining[..2]);
                    remaining = &remaining[2..];
                }
            }
        }
    }
    Ok((remaining, result))
}

/// Parse a regex literal: `/pattern/[flags]`
/// The pattern may contain `\/` escaped slashes.
fn regex_literal(input: &str) -> IResult<&str, String> {
    let (input, _) = char('/')(input)?;
    let mut pattern = String::new();
    let mut remaining = input;
    loop {
        match remaining.find(|c| c == '/' || c == '\\') {
            None => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Char,
                )));
            }
            Some(pos) => {
                pattern.push_str(&remaining[..pos]);
                remaining = &remaining[pos..];
                if remaining.starts_with("\\/") {
                    pattern.push('/');
                    remaining = &remaining[2..];
                } else if remaining.starts_with("\\\\") {
                    pattern.push_str("\\\\");
                    remaining = &remaining[2..];
                } else if remaining.starts_with('/') {
                    remaining = &remaining[1..];
                    break;
                } else {
                    pattern.push('\\');
                    remaining = &remaining[1..];
                }
            }
        }
    }
    // Optional flags (i, m, s, x) — embed into the pattern as (?flags)
    let (remaining, flags) = take_while(|c: char| "imsx".contains(c))(remaining)?;
    let full_pattern = if flags.is_empty() {
        pattern
    } else {
        format!("(?{}){}", flags, pattern)
    };
    Ok((remaining, full_pattern))
}

// ---------------------------------------------------------------------------
// Phase
// ---------------------------------------------------------------------------

fn phase_name(input: &str) -> IResult<&str, RulePhase> {
    alt((
        value(RulePhase::Connection, tag("connection")),
        value(RulePhase::RequestHeaders, tag("request_headers")),
        value(RulePhase::RequestBody, tag("request_body")),
        value(RulePhase::Upstream, tag("upstream")),
        value(RulePhase::ResponseHeaders, tag("response_headers")),
        value(RulePhase::ResponseBody, tag("response_body")),
        value(RulePhase::Logging, tag("logging")),
    ))(input)
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

fn target_name(input: &str) -> IResult<&str, Target> {
    alt((
        value(Target::Args, tag("ARGS")),
        value(Target::ArgsNames, tag("ARGS_NAMES")),
        value(Target::RequestBody, tag("REQUEST_BODY")),
        value(Target::RequestUri, tag("REQUEST_URI")),
        value(Target::RequestLine, tag("REQUEST_LINE")),
        value(Target::RemoteAddr, tag("REMOTE_ADDR")),
        value(Target::Geo, tag("GEO")),
        // REQUEST_HEADERS:Name
        map(
            pair(
                tag("REQUEST_HEADERS"),
                opt(preceded(char(':'), map(identifier, String::from))),
            ),
            |(_, opt_name)| Target::RequestHeaders(opt_name),
        ),
        // REQUEST_COOKIES:Name
        map(
            pair(
                tag("REQUEST_COOKIES"),
                opt(preceded(char(':'), map(identifier, String::from))),
            ),
            |(_, opt_name)| Target::RequestCookies(opt_name),
        ),
        // RESPONSE_HEADERS:Name
        map(
            pair(
                tag("RESPONSE_HEADERS"),
                opt(preceded(char(':'), map(identifier, String::from))),
            ),
            |(_, opt_name)| Target::ResponseHeaders(opt_name),
        ),
        value(Target::ResponseBody, tag("RESPONSE_BODY")),
        // FILES family — longest tags first so the shorter `FILES` does not
        // shadow `FILES_NAMES` / `FILES_COMBINED_SIZE`.
        value(Target::FilesCombinedSize, tag("FILES_COMBINED_SIZE")),
        value(Target::FilesNames, tag("FILES_NAMES")),
        value(Target::Files, tag("FILES")),
        // TX:var_name
        map(
            preceded(pair(tag("TX"), char(':')), map(identifier, String::from)),
            Target::TxVar,
        ),
    ))(input)
}

fn target_combinator(input: &str) -> IResult<&str, TargetCombinator> {
    alt((
        value(TargetCombinator::Or, preceded(iws, preceded(char('|'), iws))),
        value(TargetCombinator::And, preceded(iws, preceded(char('&'), iws))),
    ))(input)
}

/// Parse the full `T1 | T2 | T3` list.
fn target_expr_full(input: &str) -> IResult<&str, Vec<TargetExpr>> {
    // We parse one target, then check for "| T2", "& T2", etc.
    let (input, first_target) = target_name(input)?;
    let mut targets = vec![];
    let mut remaining = input;
    let mut current = first_target;
    loop {
        let (rest, opt_comb) = opt(target_combinator)(remaining)?;
        match opt_comb {
            Some(comb) => {
                let (rest2, next) = target_name(rest)?;
                targets.push(TargetExpr { target: current, combinator: Some(comb) });
                current = next;
                remaining = rest2;
            }
            None => {
                targets.push(TargetExpr { target: current, combinator: None });
                break;
            }
        }
    }
    Ok((remaining, targets))
}

/// Public entry: parse a target expression string.
pub fn parse_target_expr(input: &str) -> IResult<&str, Vec<TargetExpr>> {
    target_expr_full(input)
}

// ---------------------------------------------------------------------------
// Operators
// ---------------------------------------------------------------------------

fn cmp_op(input: &str) -> IResult<&str, CmpOp> {
    alt((
        value(CmpOp::Ge, tag(">=")),
        value(CmpOp::Gt, tag(">")),
        value(CmpOp::Le, tag("<=")),
        value(CmpOp::Lt, tag("<")),
        value(CmpOp::Eq, tag("==")),
    ))(input)
}

/// Parse `["word1", "word2"]`
fn word_list(input: &str) -> IResult<&str, Vec<String>> {
    delimited(
        pair(char('['), ws),
        separated_list0(
            preceded(ws, preceded(char(','), ws)),
            quoted_string,
        ),
        pair(ws, char(']')),
    )(input)
}

fn operator_expr(input: &str) -> IResult<&str, Operator> {
    alt((
        // rx /pattern/
        map(
            preceded(pair(tag("rx"), space1), regex_literal),
            Operator::Rx,
        ),
        // contains_word ["w1", "w2"]
        map(
            preceded(pair(tag("contains_word"), space1), word_list),
            Operator::ContainsWord,
        ),
        // eq "value"
        map(
            preceded(pair(tag("eq"), space1), quoted_string),
            Operator::Eq,
        ),
        // ge N
        map(
            map_res(preceded(pair(tag("ge"), space1), digit1), |s: &str| s.parse::<i64>()),
            Operator::Ge,
        ),
        // exists
        value(Operator::Exists, tag("exists")),
        // anomaly_score >= N
        map(
            tuple((
                tag("anomaly_score"),
                preceded(iws, cmp_op),
                preceded(iws, map_res(digit1, |s: &str| s.parse::<u32>())),
            )),
            |(_, op, threshold)| Operator::AnomalyScore { op, threshold },
        ),
        // ml_score("model") >= 0.87
        map(
            tuple((
                tag("ml_score"),
                delimited(char('('), quoted_string, char(')')),
                preceded(iws, cmp_op),
                preceded(iws, map_res(
                    recognize(tuple((digit1, opt(pair(char('.'), digit1))))),
                    |s: &str| s.parse::<f32>(),
                )),
            )),
            |(_, model, op, threshold)| Operator::MlScore { model, op, threshold },
        ),
        // rate_limit_exceeded(per_ip, rps=50, burst=100)
        map(
            preceded(
                tag("rate_limit_exceeded("),
                terminated(parse_rate_args, char(')')),
            ),
            |(dimension, rps, burst)| Operator::RateLimit { dimension, rps, burst },
        ),
        // !(operator)
        map(
            preceded(tag("!("), terminated(operator_expr, char(')'))),
            |inner| Operator::Not(Box::new(inner)),
        ),
    ))(input)
}

fn parse_rate_args(input: &str) -> IResult<&str, (RateLimitDim, u32, u32)> {
    let (input, dim) = preceded(
        iws,
        alt((
            value(RateLimitDim::PerIp, tag("per_ip")),
            value(RateLimitDim::PerSite, tag("per_site")),
            value(RateLimitDim::Global, tag("global")),
        )),
    )(input)?;
    let (input, _) = preceded(iws, char(','))(input)?;
    let (input, _) = preceded(iws, tag("rps="))(input)?;
    let (input, rps) = map_res(digit1, |s: &str| s.parse::<u32>())(input)?;
    let (input, _) = preceded(iws, char(','))(input)?;
    let (input, _) = preceded(iws, tag("burst="))(input)?;
    let (input, burst) = map_res(digit1, |s: &str| s.parse::<u32>())(input)?;
    Ok((input, (dim, rps, burst)))
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

fn action_expr(input: &str) -> IResult<&str, RuleAction> {
    alt((
        value(RuleAction::Score, tag("score")),
        value(RuleAction::Block, tag("block")),
        value(RuleAction::Allow, tag("allow")),
        value(RuleAction::Log, tag("log")),
        // challenge(native_pow) or challenge(captcha)
        map(
            delimited(
                pair(tag("challenge"), char('(')),
                alt((
                    value(ChallengeMode::NativePow, tag("native_pow")),
                    value(ChallengeMode::Captcha, tag("captcha")),
                )),
                char(')'),
            ),
            RuleAction::Challenge,
        ),
        // redirect("url")
        map(
            preceded(pair(tag("redirect"), char('(')), terminated(quoted_string, char(')'))),
            RuleAction::Redirect,
        ),
        // plugin_call("name", {...})
        map(
            preceded(
                pair(tag("plugin_call"), char('(')),
                terminated(parse_plugin_call_args, char(')')),
            ),
            |(name, args)| RuleAction::PluginCall { name, args },
        ),
    ))(input)
}

fn parse_plugin_call_args(input: &str) -> IResult<&str, (String, serde_json::Value)> {
    let (input, name) = quoted_string(input)?;
    let (input, _) = preceded(iws, char(','))(input)?;
    let (input, _) = iws(input)?;
    // Find the matching closing `}` for the JSON object
    if !input.starts_with('{') {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Char,
        )));
    }
    let mut depth = 0usize;
    let mut end = 0usize;
    for (i, ch) in input.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    if end == 0 {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Char,
        )));
    }
    let json_str = &input[..end];
    let remaining = &input[end..];
    let val = serde_json::from_str(json_str).unwrap_or(serde_json::Value::Object(Default::default()));
    Ok((remaining, (name, val)))
}

// ---------------------------------------------------------------------------
// Rule fields
// ---------------------------------------------------------------------------

/// Intermediate enum used while parsing rule fields.
#[derive(Debug)]
enum RuleField {
    Phase(RulePhase),
    Targets(Vec<TargetExpr>),
    Operator(Operator),
    Score(i32),
    Severity(RuleSeverity),
    Message(String),
    Action(RuleAction),
    Tags(Vec<String>),
    Expires(String),
}

fn severity_keyword(input: &str) -> IResult<&str, RuleSeverity> {
    alt((
        value(RuleSeverity::Critical, tag_no_case("critical")),
        value(RuleSeverity::High, tag_no_case("high")),
        value(RuleSeverity::Medium, tag_no_case("medium")),
        value(RuleSeverity::Low, tag_no_case("low")),
        value(RuleSeverity::Notice, tag_no_case("notice")),
    ))(input)
}

fn tag_list(input: &str) -> IResult<&str, Vec<String>> {
    delimited(
        pair(char('['), ws),
        separated_list0(
            preceded(ws, preceded(char(','), ws)),
            quoted_string,
        ),
        pair(ws, char(']')),
    )(input)
}

fn rule_field(input: &str) -> IResult<&str, RuleField> {
    let (input, _) = ws(input)?;
    let (input, key) = identifier(input)?;
    let (input, _) = preceded(iws, preceded(char(':'), iws))(input)?;

    match key {
        "phase" => map(phase_name, RuleField::Phase)(input),
        "targets" => map(parse_target_expr, RuleField::Targets)(input),
        "operator" => map(operator_expr, RuleField::Operator)(input),
        "score" => map(signed_int, RuleField::Score)(input),
        "severity" => map(severity_keyword, RuleField::Severity)(input),
        "message" | "msg" => map(quoted_string, RuleField::Message)(input),
        "action" => map(action_expr, RuleField::Action)(input),
        "tag" => map(tag_list, RuleField::Tags)(input),
        "expires" => {
            // parse date literal YYYY-MM-DD
            let (input, date) = recognize(tuple((digit1, char('-'), digit1, char('-'), digit1)))(input)?;
            Ok((input, RuleField::Expires(date.to_owned())))
        }
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

fn rule_body(input: &str) -> IResult<&str, Vec<RuleField>> {
    many0(preceded(
        ws,
        terminated(rule_field, preceded(iws, opt(char('\n')))),
    ))(input)
}

fn rule_def(input: &str) -> IResult<&str, RuleDef> {
    let (input, _) = tag("rule")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, id) = unsigned_int(input)?;
    let (input, _) = preceded(ws, char('{'))(input)?;
    let (input, fields) = rule_body(input)?;
    let (input, _) = preceded(ws, char('}'))(input)?;

    let mut def = RuleDef { id, ..Default::default() };
    for field in fields {
        match field {
            RuleField::Phase(p) => def.phase = p,
            RuleField::Targets(t) => def.targets = t,
            RuleField::Operator(o) => def.operator = o,
            RuleField::Score(s) => def.score_delta = Some(s),
            RuleField::Severity(s) => def.severity = Some(s),
            RuleField::Message(m) => def.message = Some(m),
            RuleField::Action(a) => def.action = a,
            RuleField::Tags(t) => def.tags = t,
            RuleField::Expires(_) => {} // inapplicable to rule_def
        }
    }
    Ok((input, def))
}

// ---------------------------------------------------------------------------
// Virtual patch
// ---------------------------------------------------------------------------

fn cve_id(input: &str) -> IResult<&str, String> {
    map(
        recognize(tuple((tag("CVE-"), digit1, char('-'), digit1))),
        String::from,
    )(input)
}

fn virtual_patch(input: &str) -> IResult<&str, VirtualPatch> {
    let (input, _) = tag("virtual_patch")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, cve) = cve_id(input)?;
    let (input, _) = preceded(ws, char('{'))(input)?;
    let (input, fields) = rule_body(input)?;
    let (input, _) = preceded(ws, char('}'))(input)?;

    let mut vp = VirtualPatch {
        cve,
        phase: RulePhase::RequestHeaders,
        targets: Vec::new(),
        operator: Operator::Exists,
        action: RuleAction::Block,
        message: None,
        expires: None,
    };
    for field in fields {
        match field {
            RuleField::Phase(p) => vp.phase = p,
            RuleField::Targets(t) => vp.targets = t,
            RuleField::Operator(o) => vp.operator = o,
            RuleField::Action(a) => vp.action = a,
            RuleField::Message(m) => vp.message = Some(m),
            RuleField::Expires(e) => vp.expires = Some(e),
            _ => {}
        }
    }
    Ok((input, vp))
}

// ---------------------------------------------------------------------------
// Directives
// ---------------------------------------------------------------------------

fn directive(input: &str) -> IResult<&str, Directive> {
    alt((
        // SecRuleEngine On|Off|DetectionOnly
        map(
            preceded(
                pair(tag("SecRuleEngine"), space1),
                alt((
                    value(EngineMode::On, tag("On")),
                    value(EngineMode::Off, tag("Off")),
                    value(EngineMode::DetectionOnly, tag("DetectionOnly")),
                )),
            ),
            Directive::RuleEngine,
        ),
        // SecRequestBodyAccess On|Off
        map(
            preceded(
                pair(tag("SecRequestBodyAccess"), space1),
                alt((
                    value(true, tag("On")),
                    value(false, tag("Off")),
                )),
            ),
            Directive::RequestBodyAccess,
        ),
        // SecResponseBodyAccess On|Off
        map(
            preceded(
                pair(tag("SecResponseBodyAccess"), space1),
                alt((
                    value(true, tag("On")),
                    value(false, tag("Off")),
                )),
            ),
            Directive::ResponseBodyAccess,
        ),
        // SecDefaultAction "..."
        map(
            preceded(pair(tag("SecDefaultAction"), space1), quoted_string),
            Directive::DefaultAction,
        ),
        // SecMarker "..."
        map(
            preceded(
                pair(tag("SecMarker"), space1),
                alt((quoted_string, map(take_while1(|c: char| !c.is_whitespace()), String::from))),
            ),
            Directive::SecMarker,
        ),
        // Include glob
        map(
            preceded(
                pair(tag("Include"), space1),
                map(take_while1(|c: char| !c.is_whitespace()), String::from),
            ),
            Directive::Include,
        ),
        // SecAction "..."
        map(
            preceded(pair(tag("SecAction"), space1), quoted_string),
            Directive::SecAction,
        ),
        // var name : type = value
        parse_var_decl,
        // import module.path
        map(
            preceded(
                pair(tag("import"), space1),
                map(take_while1(|c: char| !c.is_whitespace()), String::from),
            ),
            Directive::Import,
        ),
        // SecRule TARGETS "operator" "actions"
        parse_secrule_directive,
    ))(input)
}

fn parse_var_decl(input: &str) -> IResult<&str, Directive> {
    let (input, _) = tag("var")(input)?;
    let (input, _) = space1(input)?;
    let (input, name) = map(identifier, String::from)(input)?;
    let (input, _) = preceded(iws, char(':'))(input)?;
    let (input, _) = iws(input)?;
    let (input, var_type) = alt((
        value(VarType::Score, tag("score")),
        value(VarType::Int, tag("int")),
        value(VarType::Str, tag("str")),
    ))(input)?;
    let (input, _) = preceded(iws, char('='))(input)?;
    let (input, _) = iws(input)?;
    let (input, initial) = map(take_while1(|c: char| c != '\n'), String::from)(input)?;
    Ok((input, Directive::VarDecl { name, var_type, initial: initial.trim().to_owned() }))
}

fn parse_secrule_directive(input: &str) -> IResult<&str, Directive> {
    let (input, _) = tag("SecRule")(input)?;
    let (input, _) = space1(input)?;
    // targets: identifier-like string (no spaces, can have | _ :)
    let (input, targets) = map(
        take_while1(|c: char| c != ' ' && c != '\t' && c != '"' && c != '\n'),
        String::from,
    )(input)?;
    let (input, _) = space1(input)?;
    // operator: quoted string
    let (input, operator) = quoted_string(input)?;
    // actions: optional quoted string.  Chained SecRule members in CRS lack
    // their own actions string — the parent rule's `chain` action absorbs them.
    let (input, _) = take_while(|c: char| c == ' ' || c == '\t')(input)?;
    let (input, actions) = opt(parse_multiline_quoted_string)(input)?;
    let actions = actions.unwrap_or_default();
    Ok((
        input,
        Directive::SecRule(SecRuleDirective {
            targets: targets.trim().to_owned(),
            operator,
            actions,
        }),
    ))
}

/// Parse a quoted string that may have `\` line continuations (CRS style).
fn parse_multiline_quoted_string(input: &str) -> IResult<&str, String> {
    let (input, s) = quoted_string(input)?;
    // Handle backslash-newline continuations that appear outside the quote
    // (CRS uses `\` at line end before the next quoted segment).
    // For now just return the single quoted string.
    Ok((input, s))
}

// ---------------------------------------------------------------------------
// Top-level item
// ---------------------------------------------------------------------------

fn rule_item(input: &str) -> IResult<&str, RuleItem> {
    let (input, _) = ws(input)?;
    alt((
        map(rule_def, RuleItem::Rule),
        map(virtual_patch, RuleItem::VirtualPatch),
        map(directive, RuleItem::Directive),
    ))(input)
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Parse a complete SRL source string into a `RuleFile`.
pub fn parse_rule_file(source: &str) -> Result<RuleFile, ParseError> {
    let mut items = Vec::new();
    let mut remaining = source;

    loop {
        // skip ws / comments
        match ws(remaining) {
            Ok((rest, _)) => remaining = rest,
            Err(_) => break,
        }
        if remaining.is_empty() {
            break;
        }
        match rule_item(remaining) {
            Ok((rest, item)) => {
                items.push(item);
                remaining = rest;
            }
            Err(e) => {
                return Err(ParseError::from_nom(source, e));
            }
        }
    }

    Ok(RuleFile { items })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quoted_string() {
        let (rest, s) = quoted_string("\"hello world\" rest").unwrap();
        assert_eq!(s, "hello world");
        assert_eq!(rest, " rest");
    }

    #[test]
    fn test_regex_literal() {
        let (_, pat) = regex_literal("/(?i)select/").unwrap();
        assert_eq!(pat, "(?i)select");
    }

    #[test]
    fn test_regex_with_flags() {
        let (_, pat) = regex_literal("/select/i").unwrap();
        // flags appended as (?i) prefix
        assert!(pat.contains("select"));
    }

    #[test]
    fn test_phase_name() {
        let (_, p) = phase_name("request_body").unwrap();
        assert_eq!(p, RulePhase::RequestBody);
    }

    #[test]
    fn test_target_expr() {
        let (_, targets) = parse_target_expr("ARGS | REQUEST_BODY").unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].target, Target::Args);
        assert_eq!(targets[0].combinator, Some(TargetCombinator::Or));
        assert_eq!(targets[1].target, Target::RequestBody);
    }

    #[test]
    fn test_simple_rule() {
        let src = r#"
rule 942100 {
    phase     : request_body
    targets   : ARGS
    operator  : rx /(?i)(select|union)\s/
    score     : +5
    severity  : critical
    message   : "SQL injection attempt"
    action    : score
}
"#;
        let rf = parse_rule_file(src).expect("parse failed");
        assert_eq!(rf.items.len(), 1);
        if let RuleItem::Rule(rule) = &rf.items[0] {
            assert_eq!(rule.id, 942100);
            assert_eq!(rule.phase, RulePhase::RequestBody);
            assert_eq!(rule.score_delta, Some(5));
            assert!(matches!(rule.action, RuleAction::Score));
        } else {
            panic!("expected Rule, got {:?}", rf.items[0]);
        }
    }

    #[test]
    fn test_block_rule() {
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
        let rf = parse_rule_file(src).expect("parse failed");
        if let RuleItem::Rule(rule) = &rf.items[0] {
            assert!(matches!(rule.action, RuleAction::Block));
            assert!(matches!(&rule.operator, Operator::ContainsWord(words) if words.len() == 2));
        } else {
            panic!("unexpected item");
        }
    }

    #[test]
    fn test_directives() {
        let src = "SecRuleEngine On\nSecRequestBodyAccess On\n";
        let rf = parse_rule_file(src).expect("parse failed");
        assert_eq!(rf.items.len(), 2);
    }

    #[test]
    fn test_virtual_patch() {
        let src = r#"
virtual_patch CVE-2024-12345 {
    phase   : request_headers
    targets : REQUEST_URI
    operator: rx /\/vulnerable\.php\?.*cmd=/
    action  : block
    message : "Virtual patch"
    expires : 2025-12-31
}
"#;
        let rf = parse_rule_file(src).expect("parse failed");
        assert_eq!(rf.items.len(), 1);
        assert!(matches!(&rf.items[0], RuleItem::VirtualPatch(_)));
    }
}
