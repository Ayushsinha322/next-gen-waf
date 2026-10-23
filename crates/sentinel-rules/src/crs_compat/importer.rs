use anyhow::{Context, Result};
use tracing::warn;

use super::secrule::{
    parse_crs_actions, parse_crs_operator, split_crs_targets, CrsAction, CrsActions,
};
use crate::dsl::ast::{
    ChainCondition, Directive, InterpCmp, Operator, RuleAction, RuleDef, RuleFile, RuleItem,
    RulePhase, Target, TargetCombinator, TargetExclusion, TargetExpr,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Import a ModSecurity `.conf` source string and produce an SRL `RuleFile`.
///
/// `data_dir` is the directory used to resolve `@pmFromFile filename.data`
/// references.  Pass `None` to disable file loading; affected rules will be
/// emitted with an empty word list (effectively disabled).
///
/// Handles:
/// - `SecRule TARGETS "operator" "actions"` — converted to `RuleDef`
/// - `SecRule … chain` followed by continuation rules — fully supported
/// - `@pmFromFile filename` — loaded from `data_dir/filename`
/// - `SecRuleEngine On|Off|DetectionOnly`
/// - `SecRequestBodyAccess On|Off`
/// - `SecResponseBodyAccess On|Off`
/// - `SecDefaultAction "..."`
/// - `SecMarker "..."`
/// - `Include glob`
///
/// Unsupported directives are silently skipped with a warning.
pub fn import_secrule_conf_dir(
    source: &str,
    data_dir: Option<&std::path::Path>,
) -> Result<RuleFile> {
    let collapsed = collapse_continuations(source);
    // No @pmFromFile pre-expansion any more: the operator mapper reads the data
    // file itself. Substituting phrases into the source text broke on any phrase
    // containing a quote and shattered every multi-word phrase — see
    // crs_op_to_operator for the full account.
    let expanded = collapsed;
    let cleaned = comment_unknown_directives(&expanded);

    let parsed = crate::dsl::parser::parse_rule_file(&cleaned)?;

    let mut out_items: Vec<RuleItem> = Vec::new();
    // When Some, we're accumulating chain members onto the buffered rule.
    let mut pending_chain: Option<RuleDef> = None;

    for item in parsed.items {
        match item {
            RuleItem::Directive(Directive::SecRule(dir)) => {
                let actions = parse_crs_actions(&dir.actions);
                let is_chain = actions.chain;

                if let Some(ref mut pending) = pending_chain {
                    // This directive is a chain member — add its condition.
                    // A chain MEMBER usually carries no id of its own, so attribute
                    // it to the chain STARTER — the rule an operator would have to
                    // look up, and the one that goes silent if this link cannot
                    // compile.
                    let chain_id = actions.id.or(Some(pending.id));
                    let targets = parse_crs_target_str(&dir.targets, chain_id);
                    let (op_name, op_pat) = parse_crs_operator(&dir.operator);
                    match crs_op_to_operator(&op_name, &op_pat, data_dir, chain_id) {
                        Ok(operator) => {
                            // Chain members may have empty targets (bare operator
                            // that applies to the previously matched value) — we
                            // treat those as Exists stubs.
                            // The link keeps its own transformations and
                            // setvars: ModSecurity runs each chain member with
                            // its own `t:` list (the parent's do not carry
                            // over) and executes a member's non-disruptive
                            // actions when THAT member matches. Keeping only
                            // targets and operator compiled the protocol-policy
                            // rules into links that could never match — see
                            // tests/crs_chain_semantics.rs.
                            pending.chain_conditions.push(ChainCondition {
                                targets,
                                operator,
                                transforms: actions.transforms.clone(),
                                multi_match: actions.multi_match,
                                setvars: actions.setvars.clone(),
                            });

                            // Inherit the chain CHILD's anomaly-score
                            // contribution.
                            //
                            // CRS routinely puts `block` on the chain starter and
                            // the `setvar:tx.inbound_anomaly_score_plN=+...` on an
                            // inner link. Only the starter's actions were consulted
                            // for the action decision, and a child's actions are
                            // otherwise discarded here — so such a rule looked like
                            // "block, no score" and compiled to a HARD BLOCK that
                            // no site threshold could moderate.
                            //
                            // Measured consequences of that, before this fix:
                            // 943110 blocked any visitor arriving from a Google
                            // search (or from `example.com` to `www.example.com`)
                            // whenever the URL carried a session-ish parameter, and
                            // 942130 blocked query strings as ordinary as
                            // `filter=status=status` or `tab=tab`. Both are
                            // anomaly-scoring rules in CRS; neither is supposed to
                            // block on its own.
                            //
                            // A starter that really is disruptive with no score
                            // anywhere in the chain (949110's `deny`, say) has no
                            // child delta to inherit and stays Block.
                            if pending.score_delta.is_none() {
                                if let Some(delta) = actions.score_delta {
                                    pending.score_delta = Some(delta);
                                    if matches!(pending.action, RuleAction::Block) {
                                        pending.action = RuleAction::Score;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("CRS importer: skipping chain condition: {e}");
                        }
                    }

                    if !is_chain {
                        // End of chain — emit the fully-built rule.
                        out_items.push(RuleItem::Rule(
                            pending_chain
                                .take()
                                .expect("pending_chain must exist at chain end"),
                        ));
                    }
                    // If still chaining, keep pending_chain in place.
                } else {
                    // First rule in a (possibly chained) sequence.
                    match secrule_directive_to_rule_with_actions(
                        &dir.targets,
                        &dir.operator,
                        &actions,
                        data_dir,
                    ) {
                        Ok(Some(rule)) => {
                            if is_chain {
                                pending_chain = Some(rule);
                            } else {
                                out_items.push(RuleItem::Rule(rule));
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!("CRS importer: skipping SecRule: {}", e);
                        }
                    }
                }
            }
            other => {
                // Non-SecRule item breaks any open chain.
                if let Some(pending) = pending_chain.take() {
                    out_items.push(RuleItem::Rule(pending));
                }
                out_items.push(other);
            }
        }
    }

    // Finalize any trailing chain rule.
    if let Some(pending) = pending_chain.take() {
        out_items.push(RuleItem::Rule(pending));
    }

    Ok(RuleFile { items: out_items })
}

/// Convenience wrapper — no data directory (e.g. unit tests, inline snippets).
pub fn import_secrule_conf(source: &str) -> Result<RuleFile> {
    import_secrule_conf_dir(source, None)
}

// ---------------------------------------------------------------------------
// Rule conversion helpers
// ---------------------------------------------------------------------------

/// Convert a raw SecRule directive into a `RuleDef`, using pre-parsed actions.
fn secrule_directive_to_rule_with_actions(
    targets_str: &str,
    operator_str: &str,
    actions: &CrsActions,
    data_dir: Option<&std::path::Path>,
) -> Result<Option<RuleDef>> {
    let rule_id = match actions.id {
        Some(id) => id,
        None => {
            return Ok(None); // No ID — likely an orphaned chain member
        }
    };

    for u in &actions.unknown {
        warn!(rule_id, unknown_action = %u, "CRS importer: unrecognised action token");
    }

    let phase = actions.phase.unwrap_or(RulePhase::RequestBody);

    let targets = parse_crs_target_str(targets_str, Some(rule_id));
    if targets.is_empty() {
        warn!(
            rule_id,
            targets = targets_str,
            "CRS importer: skipping rule — all targets unsupported"
        );
        return Ok(None);
    }

    let (op_name, op_pattern) = parse_crs_operator(operator_str);
    let operator = crs_op_to_operator(&op_name, &op_pattern, data_dir, Some(rule_id))?;

    let rule_action = match actions.action {
        CrsAction::Block | CrsAction::Deny => {
            if actions.score_delta.is_some() {
                RuleAction::Score
            } else {
                RuleAction::Block
            }
        }
        CrsAction::Pass | CrsAction::Log | CrsAction::NoLog => RuleAction::Score,
        CrsAction::Allow => RuleAction::Allow,
    };

    let score_delta = actions.score_delta;
    Ok(Some(RuleDef {
        id: rule_id,
        phase,
        targets,
        operator,
        score_delta,
        severity: actions.severity,
        message: actions.msg.clone(),
        action: rule_action,
        tags: actions.tags.clone(),
        chain_conditions: Vec::new(),
        transforms: actions.transforms.clone(),
        skip_after: actions.skip_after.clone(),
        multi_match: actions.multi_match,
        setvars: actions.setvars.clone(),
        exclusions: parse_crs_target_exclusions(targets_str),
        remove_targets: actions
            .remove_targets
            .iter()
            .filter(|(_, target)| TargetExclusion::parse(target).is_some())
            .cloned()
            .collect(),
    }))
}

/// The `!COLLECTION:key` tokens of a target list. `token_to_target` drops
/// them as targets; they are kept here as what they are, the members the
/// rule leaves out. Read from the raw text: the target tokens are
/// upper-cased, which would turn a pattern's `\d` into `\D`.
fn parse_crs_target_exclusions(s: &str) -> Vec<TargetExclusion> {
    s.split('|')
        .filter_map(|tok| tok.trim().strip_prefix('!'))
        .filter_map(TargetExclusion::parse)
        .collect()
}

/// Public helper — kept for tests that pass actions as a raw string.
///
/// No `data_dir`, so a `@pmFromFile` reaching this path compiles to
/// `Operator::Never` rather than to a rule matching the literal filename.
pub fn secrule_directive_to_rule(
    targets_str: &str,
    operator_str: &str,
    actions_str: &str,
) -> Result<Option<RuleDef>> {
    let actions = parse_crs_actions(actions_str);
    secrule_directive_to_rule_with_actions(targets_str, operator_str, &actions, None)
}

fn parse_crs_target_str(s: &str, rule_id: Option<u32>) -> Vec<TargetExpr> {
    let mut out: Vec<TargetExpr> = split_crs_targets(s)
        .into_iter()
        .filter_map(|tok| {
            token_to_target(&tok, rule_id).map(|target| TargetExpr {
                target,
                combinator: Some(TargetCombinator::Or),
            })
        })
        .collect();
    if let Some(last) = out.last_mut() {
        last.combinator = None;
    }
    out
}

fn token_to_target(tok: &str, rule_id: Option<u32>) -> Option<Target> {
    let tok = tok.trim();
    if let Some(rest) = tok.strip_prefix('!') {
        let _ = rest;
        return None;
    }
    let is_count = tok.starts_with('&');
    let tok = tok.strip_prefix('&').unwrap_or(tok);

    let (base, sub) = if let Some(pos) = tok.find(':') {
        (&tok[..pos], Some(&tok[pos + 1..]))
    } else {
        (tok, None)
    };

    let result: Option<Target> = match base {
        // A named argument reads that argument only. A `/regex/` selector is
        // still widened to the whole collection.
        "ARGS" | "ARGS_GET" if sub.is_some_and(|s| !s.starts_with('/')) => Some(Target::ArgNamed {
            name: sub.unwrap_or_default().to_owned(),
            get_only: base == "ARGS_GET",
        }),
        "ARGS" => Some(Target::Args),
        "ARGS_NAMES" => Some(Target::ArgsNames),
        "REQUEST_BODY" | "REQUEST_BODY_RAW" => Some(Target::RequestBody),
        "REQUEST_URI" | "REQUEST_URI_RAW" => Some(Target::RequestUri),
        "REQUEST_FILENAME" => Some(Target::RequestFilename),
        "REQUEST_BASENAME" => Some(Target::RequestBasename),
        "REQUEST_METHOD" => Some(Target::RequestMethod),
        "REQUEST_PROTOCOL" => Some(Target::RequestProtocol),
        "REQBODY_PROCESSOR" => Some(Target::ReqbodyProcessor),
        "REQUEST_LINE" => Some(Target::RequestLine),
        "REQUEST_HEADERS" => Some(Target::RequestHeaders(
            sub.map(str::to_lowercase)
                .map(|s| s.trim_matches('\'').to_owned()),
        )),
        "REQUEST_COOKIES" => Some(Target::RequestCookies(sub.map(str::to_owned))),
        // The single highest-yield token in the importer: 129 CRS rules inspect
        // cookie NAMES and were all skipped before this existed.
        "REQUEST_COOKIES_NAMES" => Some(Target::RequestCookiesNames),
        "REQUEST_HEADERS_NAMES" => Some(Target::RequestHeadersNames),
        "ARGS_GET" => Some(Target::ArgsGet),
        "ARGS_GET_NAMES" => Some(Target::ArgsGetNames),
        "QUERY_STRING" => Some(Target::QueryString),
        "RESPONSE_HEADERS" => Some(Target::ResponseHeaders(sub.map(str::to_owned))),
        "RESPONSE_BODY" => Some(Target::ResponseBody),
        "REMOTE_ADDR" => Some(Target::RemoteAddr),
        "GEO" => Some(Target::Geo),
        "TX" => Some(Target::TxVar(
            sub.unwrap_or("anomaly_score").to_ascii_uppercase(),
        )),
        // The value the previous condition in the chain matched. Dropping this
        // left the condition with NO targets, which compiles to a constant
        // false and disabled eight shipped rules outright — several of them
        // negated refinements, so the effect was to switch the parent rule off
        // rather than to narrow it. See tests/crs_inert_rules.rs.
        //
        // The _NAME forms ask for the matched target's NAME rather than its
        // value, which the VM does not carry into the child. They stay
        // unsupported, but a rule left target-less by them is now RECORDED as a
        // coverage gap instead of vanishing.
        "MATCHED_VAR" => Some(Target::MatchedVar),
        "MATCHED_VARS" => Some(Target::MatchedVars),
        "MATCHED_VAR_NAME" | "MATCHED_VARS_NAMES" => None,
        "FILES" => Some(Target::Files),
        "FILES_NAMES" => Some(Target::FilesNames),
        "FILES_COMBINED_SIZE" => Some(Target::FilesCombinedSize),
        "ARGS_COMBINED_SIZE" => Some(Target::ArgsCombinedSize),
        // No on-disk temp files in a streaming proxy; per-file sizes unmodeled.
        "FILES_TMPNAMES" | "FILES_SIZES" | "FILES_TMP_CONTENT" => None,
        // XML/SOAP bodies are flattened into ARGS by the VM (element text,
        // attribute values, CDATA), so an `XML`/`XML:/xpath` target maps to
        // ARGS. The XPath sub-selector is dropped — we inspect the whole
        // flattened body rather than evaluating XPath, which is enough to catch
        // injection payloads carried inside XML.
        "XML" => Some(Target::Args),
        // Headers that arrive in the BODY, one value per part header line. The
        // whole of REQUEST-922-MULTIPART-ATTACK targets this and nothing else,
        // so without it that file imported zero rules and the multipart attack
        // family was unreachable no matter how a site was configured.
        //
        // The sub-selector is a PART name (the form field), not a header name:
        // `&MULTIPART_PART_HEADERS:_charset_` asks whether a `_charset_` field
        // was submitted at all, which is what rule 922100 gates on.
        "MULTIPART_PART_HEADERS" => Some(Target::MultipartPartHeaders(
            sub.map(|s| s.trim_matches('\'').to_ascii_lowercase()),
        )),
        "MULTIPART_FILENAME" => Some(Target::Files),
        "MULTIPART_NAME" => Some(Target::FilesNames),
        other => {
            warn!(
                rule_id,
                target = other,
                "CRS importer: unknown target token, skipping"
            );
            None
        }
    };
    if is_count {
        result.map(|t| Target::CountOf(Box::new(t)))
    } else {
        result
    }
}

/// `data_dir` resolves `@pmFromFile filename.data`.
///
/// WHY THE FILE IS READ HERE AND NOT SUBSTITUTED INTO THE SOURCE TEXT
///
/// It used to be expanded textually before parsing — `@pmFromFile x.data` was
/// rewritten to `@pm phrase1 phrase2 …` and the operator arm then split that on
/// whitespace. That produced two defects, and fixing either alone makes things
/// worse:
///
///   * A phrase containing a double quote terminated the enclosing operator
///     string, so the WHOLE FILE failed to import. Three shipped CRS files were
///     lost this way — RESPONSE-952 (Java data leakage), RESPONSE-953 (PHP data
///     leakage) and RESPONSE-955 (web shells) — because their data files contain
///     1, 173 and 11 quotes respectively.
///
///   * Joining phrases with spaces and splitting on whitespace SHATTERED
///     multi-word phrases. 1,782 of the 1,853 phrases in php-errors.data contain
///     a space, so a rule meant to match "Fatal error: Uncaught" would instead
///     match the bare word "be" or "error" anywhere in a response body.
///
/// Fixing only the quoting would therefore have enabled three files whose rules
/// match single common English words against every response — a far worse outcome
/// than leaving them disabled. Reading the file at operator-construction time
/// removes both defects at once: no quoting to get wrong, and one phrase per line
/// preserved exactly as CRS wrote it.
/// Map a ModSecurity operator name to the interpolated comparison that models
/// it, or `None` when a `%{...}` pattern cannot be supported for that operator.
///
/// Intentionally narrow: `@rx`/`@pm` would need a regex or automaton rebuilt per
/// request, and no shipped CRS rule uses a macro with either.
fn interp_cmp_for(op: &str) -> Option<InterpCmp> {
    Some(match op {
        "ge" => InterpCmp::Ge,
        "gt" => InterpCmp::Gt,
        "lt" => InterpCmp::Lt,
        "streq" => InterpCmp::Streq,
        "within" => InterpCmp::Within,
        // Lowercase only — see the note on `unconditionalmatch`. The camelCase
        // alternate was dead, not harmful, because the lowercase arm precedes it.
        "endswith" => InterpCmp::EndsWith,
        _ => return None,
    })
}

/// Parse a `@validateByteRange` spec: comma-separated single bytes and
/// inclusive ranges, e.g. `1-255` or `9,10,13,32-126,128-255`.
///
/// ModSecurity's semantics: the spec lists the bytes that are ALLOWED, and the
/// operator fires when a value contains anything else. Parsing is strict — a
/// malformed spec must fail loudly at import rather than quietly widen or narrow
/// what the rule permits, because either direction is wrong in a way nobody
/// would notice: too wide and 920270 stops catching NUL bytes, too narrow and it
/// fires on ordinary text.
fn parse_byte_ranges(spec: &str) -> Result<Vec<(u8, u8)>> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (lo, hi) = match part.split_once('-') {
            Some((a, b)) => (
                a.trim()
                    .parse::<u8>()
                    .with_context(|| format!("bad low byte {a:?}"))?,
                b.trim()
                    .parse::<u8>()
                    .with_context(|| format!("bad high byte {b:?}"))?,
            ),
            None => {
                let v = part
                    .parse::<u8>()
                    .with_context(|| format!("bad byte {part:?}"))?;
                (v, v)
            }
        };
        if lo > hi {
            anyhow::bail!("inverted range {lo}-{hi}");
        }
        out.push((lo, hi));
    }
    if out.is_empty() {
        anyhow::bail!("no byte ranges given");
    }
    Ok(out)
}

/// `rule_id` is carried purely so the "disabled" and "unknown" warnings can name
/// the rule they silenced. Without it the log said only which OPERATOR was
/// unsupported, leaving an operator to grep the CRS sources by hand to learn what
/// coverage they had actually lost — which is why four disabled rules sat
/// unnoticed for months.
pub(crate) fn crs_op_to_operator(
    op_name: &str,
    pattern: &str,
    data_dir: Option<&std::path::Path>,
    rule_id: Option<u32>,
) -> Result<Operator> {
    // `%{...}` patterns cannot be compiled to a fixed pattern; they are expanded
    // per request instead (Operator::Interpolated).
    //
    // The negation handling below is deliberate and load-bearing. A SUPPORTED
    // comparison is safe to wrap in `Not`, because an unresolvable macro yields
    // `Absent` and `Not(Absent)` is `false`. An UNSUPPORTED one falls back to
    // `Never`, which must NOT be negated: `Never` pushes `false`, so `Not(Never)`
    // would be *always true* — turning a rule like
    // `!@rx %{something}` into "block everything". That is why this check stays
    // ahead of the generic `!` strip further down.
    if pattern.contains("%{") {
        let (negated, base) = match op_name.strip_prefix('!') {
            Some(b) => (true, b),
            None => (false, op_name),
        };
        return Ok(match interp_cmp_for(base) {
            Some(cmp) => {
                let op = Operator::Interpolated {
                    cmp,
                    raw: pattern.to_owned(),
                };
                if negated {
                    Operator::Not(Box::new(op))
                } else {
                    op
                }
            }
            None => {
                warn!(
                    rule_id,
                    op = op_name,
                    pattern,
                    "CRS importer: `%{{...}}` interpolation is not supported for this \
                     operator — rule disabled"
                );
                // Never, NOT Not(Never) — see above.
                Operator::Never
            }
        });
    }

    if let Some(inner_name) = op_name.strip_prefix('!') {
        let inner = crs_op_to_operator(inner_name, pattern, data_dir, rule_id)?;
        return Ok(Operator::Not(Box::new(inner)));
    }

    match op_name {
        "rx" => Ok(Operator::Rx(pattern.to_owned())),
        // Inline @pm IS whitespace-separated words — that is its documented
        // meaning in a rule file, so splitting here is correct.
        "pm" => {
            let words: Vec<String> = pattern.split_whitespace().map(String::from).collect();
            Ok(Operator::ContainsWord(words))
        }
        // @pmFromFile is one PHRASE PER LINE, and phrases contain spaces.
        "pmfromfile" => {
            let filename = pattern.trim();
            let Some(dir) = data_dir else {
                warn!(
                    filename,
                    "@pmFromFile: no data_dir provided — rule disabled rather than \
                     left matching the literal filename"
                );
                return Ok(Operator::Never);
            };
            let path = dir.join(filename);
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    let phrases: Vec<String> = content
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .map(String::from)
                        .collect();
                    if phrases.is_empty() {
                        warn!(file = %path.display(), "@pmFromFile: empty word list — rule disabled");
                        Ok(Operator::Never)
                    } else {
                        Ok(Operator::ContainsWord(phrases))
                    }
                }
                Err(e) => {
                    warn!(file = %path.display(), "@pmFromFile: cannot read ({e}) — rule disabled");
                    Ok(Operator::Never)
                }
            }
        }
        "contains" => Ok(Operator::ContainsWord(vec![pattern.to_owned()])),
        "beginswith" => Ok(Operator::Rx(format!("^{}", regex::escape(pattern)))),
        "endswith" => Ok(Operator::Rx(format!("{}$", regex::escape(pattern)))),
        "streq" | "eq" => Ok(Operator::Eq(pattern.to_owned())),
        "ge" => pattern
            .parse::<i64>()
            .map(Operator::Ge)
            .map_err(|_| anyhow::anyhow!("invalid integer in @ge: {}", pattern)),
        "lt" => {
            // @lt N → less-than comparison; expressed as Not(Ge(N)).
            // Used by CRS for TX:DETECTION_PARANOIA_LEVEL skip-gate rules.
            pattern
                .parse::<i64>()
                .map(|n| Operator::Not(Box::new(Operator::Ge(n))))
                .map_err(|_| anyhow::anyhow!("invalid integer in @lt: {}", pattern))
        }
        "le" => {
            // @le N → less-than-or-equal; expressed as Not(Ge(N+1)).
            pattern
                .parse::<i64>()
                .map(|n| Operator::Not(Box::new(Operator::Ge(n + 1))))
                .map_err(|_| anyhow::anyhow!("invalid integer in @le: {}", pattern))
        }
        "within" => {
            let words: Vec<String> = pattern.split_whitespace().map(String::from).collect();
            Ok(Operator::ContainsWord(words))
        }
        // `parse_crs_operator` lowercases the operator name, so these arms MUST be
        // spelled in lowercase. They were written in ModSecurity's camelCase and
        // were therefore unreachable: `@unconditionalMatch` fell through to the
        // catch-all and compiled to `Never`, which is the entire reason CRS 901320
        // could not fire. `@noMatch` had the same defect but appears nowhere in
        // shipped CRS, so it cost nothing — yet.
        "exists" | "unconditionalmatch" => Ok(Operator::Exists),
        "nomatch" => Ok(Operator::Not(Box::new(Operator::Exists))),
        // Real libinjection-based detection (tokenising SQLi/XSS analysis),
        // replacing the previous coarse regex approximations.
        "detectsqli" => Ok(Operator::DetectSqli),
        "detectxss" => Ok(Operator::DetectXss),
        "gt" => pattern
            .parse::<i64>()
            .map(|n| Operator::Ge(n + 1))
            .map_err(|_| anyhow::anyhow!("invalid integer in @gt: {}", pattern)),
        // @ipMatch is now implemented natively instead of being disabled. The pattern is
        // a comma- or space-separated list of addresses/CIDRs.
        // @validateByteRange is now implemented instead of being disabled. It
        // restores 920270 (null byte) and 920271 (non-printable characters),
        // both of which previously loaded as `Never` — present in the ruleset,
        // incapable of matching.
        "validatebyterange" => {
            let ranges = parse_byte_ranges(pattern)
                .with_context(|| format!("invalid @validateByteRange spec: {pattern}"))?;
            Ok(Operator::ValidateByteRange(ranges))
        }
        "ipmatch" => Ok(Operator::IpMatch(
            pattern
                .split([',', ' '])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
        )),
        // @rbl looked up a DNS blocklist, which we deliberately do not do on the request
        // path (an unbounded network round-trip per request). In CRS, @rbl appears in
        // the SSRF/RFI rules to ask "is this host somewhere it should not be" — which
        // the native SSRF operator answers locally and more thoroughly, across every
        // encoding of an internal address. Mapping it here restores the coverage those
        // rules were written to provide instead of leaving them inert.
        "rbl" => Ok(Operator::SsrfUrl),
        // Both encoding validators are now implemented instead of disabled. They
        // backed CRS 920220/920240 (URL encoding abuse) and 920250 (UTF-8
        // encoding abuse); each sat in a chain CHILD, so compiling the child to
        // `Never` made the whole chain unable to fire while the parent rule still
        // counted as loaded.
        "validateurlencoding" => Ok(Operator::ValidateUrlEncoding),
        "validateutf8encoding" => Ok(Operator::ValidateUtf8Encoding),
        "validateschema"
        | "validatedtd"
        | "verifycc"
        | "verifycpf"
        | "verifyssn"
        | "geolookup"
        // @ipMatchF/@ipMatchFromFile need the referenced file's contents, which the
        // importer does not read. Left disabled deliberately rather than silently
        // matching nothing under a name that implies it works.
        | "ipmatchf"
        | "ipmatchfromfile"
        | "fuzzyhash"
        | "inspectfile"
        | "lookup" => {
            warn!(
                rule_id,
                op = op_name,
                "CRS importer: unsupported operator '{op_name}' — rule disabled"
            );
            Ok(Operator::Never)
        }
        other => {
            warn!(
                rule_id,
                op = other,
                "CRS importer: unknown operator '{other}' — rule disabled"
            );
            Ok(Operator::Never)
        }
    }
}

// ---------------------------------------------------------------------------
// ModSecurity directive preprocessing
// ---------------------------------------------------------------------------

const KNOWN_DIRECTIVES: &[&str] = &[
    "SecRule",
    "SecRuleEngine",
    "SecRequestBodyAccess",
    "SecResponseBodyAccess",
    "SecDefaultAction",
    "SecMarker",
    "SecAction",
];

fn comment_unknown_directives(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    for line in source.lines() {
        let trimmed = line.trim_start();
        let first_token = trimmed
            .split(|c: char| c.is_whitespace())
            .next()
            .unwrap_or("");

        let is_known = KNOWN_DIRECTIVES.iter().any(|d| first_token == *d);
        let is_unknown_sec = first_token.starts_with("Sec") && !is_known;

        if is_unknown_sec {
            out.push_str("# [crs-compat skipped] ");
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn collapse_continuations(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('\n') => {
                    chars.next();
                    out.push(' ');
                }
                Some('\\') => {
                    chars.next();
                    out.push('\\');
                    out.push('\\');
                }
                _ => out.push(c),
            }
        } else {
            out.push(c);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_unknown_sec_directives() {
        let src = r#"SecComponentSignature "OWASP_CRS/4.7.0"
SecAuditEngine RelevantOnly
SecRule ARGS "@rx evil" "id:1,phase:2,block,msg:'x'"
"#;
        let rf = import_secrule_conf(src).expect("import failed despite unknown directives");
        assert_eq!(
            rf.items
                .iter()
                .filter(|i| matches!(i, RuleItem::Rule(_)))
                .count(),
            1
        );
    }

    #[test]
    fn import_simple_secrule() {
        let src = r##"SecRule ARGS "@rx (?i)(select|union)" "id:942100,phase:2,block,msg:'SQL Injection',severity:'CRITICAL'""##;
        let rf = import_secrule_conf(src).expect("import failed");
        assert_eq!(rf.items.len(), 1);
        if let RuleItem::Rule(rule) = &rf.items[0] {
            assert_eq!(rule.id, 942100);
            assert_eq!(rule.phase, RulePhase::RequestBody);
            assert!(matches!(&rule.operator, Operator::Rx(_)));
        } else {
            panic!("expected Rule");
        }
    }

    #[test]
    fn import_multi_target() {
        let src = r#"SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx select" "id:100,phase:2,pass""#;
        let rf = import_secrule_conf(src).expect("import");
        if let RuleItem::Rule(rule) = &rf.items[0] {
            assert!(!rule.targets.is_empty());
        }
    }

    #[test]
    fn chain_directive_combines_conditions() {
        let src = r#"SecRule ARGS "@rx select" "id:100,phase:2,pass,log,chain"
SecRule REQUEST_HEADERS:User-Agent "@rx sqlmap" "t:none"
"#;
        let rf = import_secrule_conf(src).expect("import");
        let rules: Vec<_> = rf
            .items
            .iter()
            .filter_map(|i| {
                if let RuleItem::Rule(r) = i {
                    Some(r)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(rules.len(), 1, "chained rules should produce one RuleDef");
        assert_eq!(rules[0].id, 100);
        assert_eq!(
            rules[0].chain_conditions.len(),
            1,
            "one chain condition expected"
        );
    }

    #[test]
    fn chain_triple_combines_all() {
        let src = r#"SecRule ARGS "@rx foo" "id:200,phase:2,pass,chain"
SecRule ARGS "@rx bar" "chain"
SecRule ARGS "@rx baz" "t:none"
"#;
        let rf = import_secrule_conf(src).expect("import");
        let rules: Vec<_> = rf
            .items
            .iter()
            .filter_map(|i| {
                if let RuleItem::Rule(r) = i {
                    Some(r)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].chain_conditions.len(), 2);
    }

    #[test]
    fn pmfromfile_without_dir_is_disabled_not_matching_a_placeholder() {
        // Contract CHANGED deliberately. This used to assert that a placeholder
        // word was injected so "the AC set still compiles" — which left a rule
        // that matches the literal string `__sentinel_pmfromfile_missing__`. It
        // compiles, it counts towards the rule total, and it can never fire on
        // real traffic: an inert rule wearing a working rule's clothes.
        //
        // Operator::Never says the same thing honestly, and is what the coverage
        // census then reports.
        let src = r#"SecRule ARGS "@pmFromFile scanners.data" "id:300,phase:2,block""#;
        let rf = import_secrule_conf(src).expect("import");
        let rules: Vec<_> = rf
            .items
            .iter()
            .filter_map(|i| {
                if let RuleItem::Rule(r) = i {
                    Some(r)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(rules.len(), 1, "rule should still be emitted");
        assert!(
            matches!(rules[0].operator, Operator::Never),
            "with no data_dir the rule must be disabled, not matching a \
             placeholder. Got {:?}",
            rules[0].operator
        );
    }

    #[test]
    fn pmfromfile_with_dir_loads_words() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let file_path = dir.path().join("test.data");
        let mut f = std::fs::File::create(&file_path).unwrap();
        writeln!(f, "# comment").unwrap();
        writeln!(f, "sqlmap").unwrap();
        writeln!(f, "nikto").unwrap();

        let src =
            r#"SecRule REQUEST_HEADERS:User-Agent "@pmFromFile test.data" "id:400,phase:1,block""#;
        let rf = import_secrule_conf_dir(src, Some(dir.path())).expect("import");
        let rules: Vec<_> = rf
            .items
            .iter()
            .filter_map(|i| {
                if let RuleItem::Rule(r) = i {
                    Some(r)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(rules.len(), 1);
        if let Operator::ContainsWord(words) = &rules[0].operator {
            assert!(words.contains(&"sqlmap".to_owned()));
            assert!(words.contains(&"nikto".to_owned()));
            assert!(!words.iter().any(|w| w.starts_with('#')));
        } else {
            panic!("expected ContainsWord operator");
        }
    }

    #[test]
    fn lt_operator_maps_to_not_ge() {
        let src = r#"SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 2" "id:500,phase:1,pass,nolog""#;
        let rf = import_secrule_conf(src).expect("import");
        let rules: Vec<_> = rf
            .items
            .iter()
            .filter_map(|i| {
                if let RuleItem::Rule(r) = i {
                    Some(r)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(rules.len(), 1);
        assert!(
            matches!(&rules[0].operator, Operator::Not(inner) if matches!(inner.as_ref(), Operator::Ge(2))),
            "expected Not(Ge(2)) for @lt 2"
        );
    }

    #[test]
    fn count_target_with_gt_operator() {
        let src = r#"SecRule &REQUEST_HEADERS:Content-Type "@gt 1" "id:920620,phase:1,block,msg:'Multiple Content-Type Request Headers',severity:'CRITICAL'""#;
        let rf = import_secrule_conf(src).expect("import");
        let rules: Vec<_> = rf
            .items
            .iter()
            .filter_map(|i| {
                if let RuleItem::Rule(r) = i {
                    Some(r)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(rules.len(), 1);
        assert!(
            matches!(&rules[0].targets[0].target, Target::CountOf(inner) if matches!(inner.as_ref(), Target::RequestHeaders(Some(h)) if h == "content-type")),
            "expected CountOf(RequestHeaders(content-type)) target"
        );
        assert!(
            matches!(&rules[0].operator, Operator::Ge(2)),
            "expected Ge(2) for @gt 1"
        );
    }

    #[test]
    fn count_target_does_not_block_clean_get() {
        use crate::RuleEngine;
        use sentinel_core::context::{Phase, RequestContext, WafDecision};
        use std::net::{IpAddr, Ipv4Addr};

        let src = r#"SecRule &REQUEST_HEADERS:Content-Type "@gt 1" "id:920620,phase:1,block,msg:'Multiple Content-Type',severity:'CRITICAL'""#;
        let engine = RuleEngine::from_crs_conf(src).expect("engine");

        let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        let decision = engine.evaluate(&mut ctx, Phase::RequestHeaders, 0);
        assert!(
            !matches!(decision, WafDecision::Block),
            "clean GET with no Content-Type must not be blocked by 920620"
        );
    }
}
