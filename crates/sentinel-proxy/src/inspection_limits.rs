//! The proxy's side of the rule engine's inspection limits (`InspectionLimits`
//! in sentinel-core): saying so when learning mode forwards a request the
//! engine refused to finish inspecting, and telling the operator what to change.
//!
//! The engine itself records the refusal (a built-in CRITICAL match, a Block
//! and its reason, and the `sentinel_inspection_limit_exceeded_total` count);
//! the site's mode then governs it like any other verdict.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sentinel_core::config::SiteConfig;
use sentinel_core::context::{InspectionLimit, Phase, RequestContext, WafDecision};
use tracing::warn;

/// The limit the engine refused the request for during `phase`, if it did.
/// A request records a refusal once, in the phase that first met the limit.
fn refusal_in(ctx: &RequestContext, phase: &Phase) -> Option<InspectionLimit> {
    ctx.rule_matches
        .iter()
        .filter(|m| &m.phase == phase)
        .find_map(|m| InspectionLimit::of_rule(&m.rule_id))
}

/// Whether the engine refused to finish inspecting this request, in any
/// phase so far.
pub(crate) fn refused(ctx: &RequestContext) -> bool {
    ctx.rule_matches
        .iter()
        .any(|m| InspectionLimit::of_rule(&m.rule_id).is_some())
}

/// At most one learning-mode WARN per site and limit in this long.
const WARN_EVERY: Duration = Duration::from_secs(10);

/// When each site and limit last logged its WARN, and how many it has held
/// back since.
type WarnLog = HashMap<(String, &'static str), (Instant, u64)>;

static WARNED: Mutex<Option<WarnLog>> = Mutex::new(None);

/// Whether a WARN for `site` and `limit` is due at `now`: `Some(held back
/// since the last one)`, or `None` within `WARN_EVERY` of it.
fn warning_due(log: &mut WarnLog, site: &str, limit: InspectionLimit, now: Instant) -> Option<u64> {
    match log.get_mut(&(site.to_owned(), limit.reason())) {
        Some((last, held)) if now.saturating_duration_since(*last) < WARN_EVERY => {
            *held += 1;
            None
        }
        Some((last, held)) => {
            *last = now;
            Some(std::mem::take(held))
        }
        None => {
            log.insert((site.to_owned(), limit.reason()), (now, 0));
            Some(0)
        }
    }
}

/// Called once the site's mode has been applied to `phase`'s verdict. A
/// refused request that learning mode lets through reaches the origin partly
/// uninspected, which is a coverage gap and must not be silent — the same rule
/// the oversize-body path follows for a body it forwards unread.
///
/// Throttled, unlike that path: a client can send refused requests at any
/// rate, and one WARN each let it write the log at that rate. The event and
/// `sentinel_inspection_limit_exceeded_total{reason}` still record every one;
/// the log says it is happening, once per site and limit every `WARN_EVERY`,
/// with how many it held back.
pub(crate) fn warn_if_forwarded(ctx: &RequestContext, site: &SiteConfig, phase: &Phase) {
    if ctx.decision == WafDecision::Block || !ctx.would_block {
        return;
    }
    let Some(limit) = refusal_in(ctx, phase) else {
        return;
    };
    let due = {
        let mut warned = WARNED.lock().unwrap_or_else(|e| e.into_inner());
        warning_due(
            warned.get_or_insert_with(HashMap::new),
            &site.id,
            limit,
            Instant::now(),
        )
    };
    if let Some(held_back) = due {
        warn!(
            site = %site.id,
            limit = limit.setting(),
            reason = ctx.block_reason.as_deref().unwrap_or(""),
            // Like requests not logged since this site's last such warning.
            held_back,
            "request not fully inspected (inspection limit) — NOT rejected (learning mode); \
             recorded as would-block"
        );
    }
}

/// The remediation for an event decided by an inspection-limit refusal. The
/// generic advice for a rule hit — exclude the rule, or raise the anomaly
/// threshold — changes nothing here: the refusal is not a rule and adds no
/// score.
pub(crate) fn remediation(limit: InspectionLimit, ctx: &RequestContext, site: &str) -> String {
    let l = &ctx.inspection_limits;
    let now = match limit {
        InspectionLimit::Args => format!("{} arguments", l.max_args),
        InspectionLimit::ArgBytes => format!("{} bytes", l.max_arg_bytes),
        InspectionLimit::Time => format!("{} ms", l.time_budget_ms),
    };
    // The legitimate traffic that meets each limit, so the operator can tell
    // it from a request built to be expensive.
    let legitimate = match limit {
        InspectionLimit::Args => {
            "Legitimate requests that reach it are forms or JSON documents with thousands of \
             fields or array items. "
        }
        InspectionLimit::ArgBytes => {
            "Legitimate requests that reach it are usually uploads read as text: a file sent \
             as base64 inside JSON or XML; a raw text, CSV or binary body (text/plain, \
             application/octet-stream, multipart/related, or no Content-Type), which is one \
             argument of its whole length; or NDJSON sent as application/json, which is not \
             one JSON document and is read whole. "
        }
        InspectionLimit::Time => "",
    };
    format!(
        "This request went past site '{site}''s inspection limit {setting} (now {now}), so the \
         rule engine stopped rather than judge it on part of its content. {legitimate}If such \
         requests are legitimate, raise {setting} in the site's policy; each increase lets one \
         request cost more inspection time, which is what the limit bounds. A burst of these \
         from one source usually means requests built to be expensive to inspect.",
        setting = limit.setting(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::websocket::{self, MessageInspector};
    use crate::{block_response, explain_event, phase2_body, RuleEngineMap, WsSiteInspector};
    use arc_swap::ArcSwap;
    use sentinel_core::config::{UpstreamConfig, WafConfig, WafMode};
    use sentinel_core::context::{InspectionLimits, RuleMatch, Severity};
    use sentinel_ml::MlEngine;
    use sentinel_rules::RuleEngine;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;

    /// Enough phase-2 rules over ARGS that the time budget is read several
    /// times; rule 29 fires on the last argument, so a request that reaches it
    /// was inspected in full.
    fn rules() -> String {
        let mut src = String::from(
            "SecRule ARGS \"@rx ^last-value$\" \"id:29,phase:2,pass,msg:'last argument seen'\"\n",
        );
        for i in 0..40 {
            src.push_str(&format!(
                "SecRule ARGS \"@rx never-{i}\" \"id:{},phase:2,pass\"\n",
                100 + i
            ));
        }
        src
    }

    /// A site whose policy is `policy`, parsed as the control plane's JSON is,
    /// so the limits reach the request through `WafConfig` exactly as in
    /// production.
    fn site(mode: WafMode, policy: serde_json::Value) -> SiteConfig {
        let mut waf: WafConfig = serde_json::from_value(policy).expect("policy");
        waf.mode = mode;
        SiteConfig {
            id: "limits".into(),
            tenant_id: String::new(),
            domains: vec!["limits.local".into()],
            upstream: UpstreamConfig {
                load_balancer: sentinel_core::config::LoadBalancerStrategy::RoundRobin,
                servers: vec![],
                health_check: None,
                timeout_secs: None,
                websocket: true,
                host_header: None,
                keepalive: true,
                connect_timeout_secs: None,
                sni_name: None,
            },
            waf,
            plugins: vec![],
            tls: Default::default(),
            origin: Default::default(),
        }
    }

    fn engines(site: &SiteConfig) -> RuleEngineMap {
        let mut map = RuleEngineMap::new();
        map.insert(
            site.id.clone(),
            RuleEngine::from_crs_conf(&rules()).unwrap(),
        );
        map
    }

    /// A urlencoded POST to `site`, stamped as routing stamps it.
    fn post(site: &SiteConfig, uri: &str, body: &str) -> RequestContext {
        let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        ctx.method = http::Method::POST;
        ctx.uri = uri.parse().unwrap();
        ctx.request_headers.insert(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        ctx.request_body = Some(bytes::Bytes::from(body.to_owned()));
        ctx.site_id = Some(site.id.clone());
        ctx.inspection_limits = site.waf.inspection_limits();
        ctx.advance_phase(Phase::RequestBody);
        ctx
    }

    fn body_phase(site: &SiteConfig, uri: &str, body: &str) -> RequestContext {
        let mut ctx = post(site, uri, body);
        let ml = MlEngine::new(64, 64, None);
        phase2_body(&mut ctx, Some(site), &engines(site), &ml).unwrap();
        ctx
    }

    /// Each limit, past it: blocking mode refuses — 413, 414 for a query string
    /// over it on its own, 403 for the time budget — with the advice to raise
    /// the limit; learning mode passes the request on as a recorded
    /// would-block. Within the limits nothing changes in either mode.
    #[test]
    fn each_limit_blocks_in_blocking_mode_and_is_recorded_in_learning_mode() {
        let cases = [
            (
                InspectionLimit::Args,
                serde_json::json!({"max_inspected_args": 3}),
                "/f",
                "a=v&b=v&c=last-value&d=v",
                413,
                ("/f", "a=v&b=v&c=last-value"),
            ),
            (
                InspectionLimit::Args,
                serde_json::json!({"max_inspected_args": 3}),
                "/f?a=v&b=v&c=v&d=v",
                "e=last-value",
                414,
                ("/f?a=v&b=v", "c=last-value"),
            ),
            (
                InspectionLimit::ArgBytes,
                serde_json::json!({"max_inspected_arg_bytes": 12}),
                "/f",
                "a=last-value&b=v",
                413,
                ("/f", "c=last-value"),
            ),
            (
                InspectionLimit::Time,
                serde_json::json!({"inspection_time_budget_ms": 50}),
                "/f",
                "a=last-value",
                403,
                ("/f", "a=last-value"),
            ),
        ];
        for (limit, policy, uri, body, status, (ok_uri, ok_body)) in cases {
            for mode in [WafMode::Blocking, WafMode::Learning] {
                let s = site(mode.clone(), policy.clone());
                if limit == InspectionLimit::Time {
                    sentinel_rules::test_hooks::set_eval_clock_step(Duration::from_millis(51));
                }
                let past = body_phase(&s, uri, body);
                sentinel_rules::test_hooks::set_eval_clock_step(Duration::ZERO);
                let what = format!("{limit:?} {mode:?} {uri} {body}");
                let refusal = past
                    .rule_matches
                    .iter()
                    .find(|m| m.rule_id == limit.rule_id());
                assert!(refusal.is_some(), "{what}: {:?}", past.rule_matches);
                let reason = past.block_reason.clone().unwrap_or_default();
                assert!(
                    reason.starts_with("inspection limit exceeded: "),
                    "{what}: {reason}"
                );
                if mode == WafMode::Blocking {
                    assert_eq!(past.decision, WafDecision::Block, "{what}");
                    assert!(!past.would_block, "{what}");
                    assert_eq!(block_response(&past).status().as_u16(), status, "{what}");
                    let m = refusal.unwrap();
                    let (message, advice) = explain_event(&past, "BLOCK", &m.rule_id, &m.message);
                    // Named as the finding, with no field to exclude.
                    let finding = format!("{} (rule {}, severity Critical", m.message, m.rule_id);
                    assert!(message.contains(&finding), "{message}");
                    assert!(advice.contains(limit.setting()), "{advice}");
                } else {
                    assert_eq!(past.decision, WafDecision::Log, "{what}");
                    assert!(past.would_block, "{what}");
                }

                let within = body_phase(&s, ok_uri, ok_body);
                assert_eq!(within.decision, WafDecision::Allow, "{what}: within");
                assert!(
                    within.rule_matches.iter().any(|m| m.rule_id == "29"),
                    "{what}: within the limits every argument is inspected"
                );
            }
        }
    }

    fn inspector(site: SiteConfig) -> WsSiteInspector {
        WsSiteInspector {
            engines: Arc::new(ArcSwap::new(Arc::new(engines(&site)))),
            site,
            ml_engine: Arc::new(MlEngine::new(64, 64, None)),
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            uri: "/ws".parse().unwrap(),
            tenant_id: None,
            tls_fingerprint: None,
            enforcement_mode: None,
            anomaly_threshold: None,
            paranoia: "1".into(),
            log_headers: http::HeaderMap::new(),
        }
    }

    /// A WebSocket message is inspected with no site config in scope but its
    /// socket's: it is held to the same limits as a request.
    #[test]
    fn a_websocket_message_past_a_limit_is_refused_or_recorded_by_mode() {
        let policy = serde_json::json!({"max_inspected_args": 3});
        let past = br#"{"a":"v","b":"v","c":"v","d":"v"}"#;
        let within = br#"{"a":"v","b":"v","c":"v"}"#;
        let blocking = inspector(site(WafMode::Blocking, policy.clone()));
        assert_eq!(
            blocking.inspect(past),
            websocket::Verdict::Refuse(websocket::CLOSE_POLICY_VIOLATION)
        );
        assert_eq!(blocking.inspect(within), websocket::Verdict::Forward);
        let learning = inspector(site(WafMode::Learning, policy));
        assert_eq!(learning.inspect(past), websocket::Verdict::Forward);
    }

    fn refused(phase: Phase) -> RequestContext {
        let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        ctx.inspection_limits = InspectionLimits {
            max_args: 4096,
            max_arg_bytes: 1 << 20,
            time_budget_ms: 1000,
        };
        ctx.rule_matches.push(RuleMatch {
            rule_id: InspectionLimit::ArgBytes.rule_id().into(),
            message: "Request not fully inspected".into(),
            severity: Severity::Critical,
            score: 0,
            target: String::new(),
            phase,
            matched_value: String::new(),
        });
        ctx
    }

    #[test]
    fn the_refusal_is_found_only_in_the_phase_that_recorded_it() {
        let ctx = refused(Phase::RequestHeaders);
        assert_eq!(
            refusal_in(&ctx, &Phase::RequestHeaders),
            Some(InspectionLimit::ArgBytes)
        );
        assert_eq!(refusal_in(&ctx, &Phase::RequestBody), None);
    }

    /// Learning mode forwards every refused request, and logged a WARN for
    /// each: a client could write the log at its own request rate. The event
    /// and the counter record each one; the log says so once per site and
    /// limit every `WARN_EVERY`.
    #[test]
    fn learning_mode_warns_once_per_site_and_limit_not_once_per_request() {
        let mut s = site(
            WafMode::Learning,
            serde_json::json!({"max_inspected_args": 3}),
        );
        // A site of its own: the throttle is process-wide.
        s.id = "warn-throttle".into();
        for _ in 0..50 {
            let ctx = body_phase(&s, "/f", "a=v&b=v&c=v&d=v");
            assert!(ctx.would_block);
        }
        // The throttle's own record: one WARN logged, the other 49 held back.
        // (Counting log events through a thread-scoped subscriber was flaky:
        // tracing caches whether a callsite is enabled process-wide, and other
        // test threads moving that cache let the WARN miss the subscriber —
        // GitLab pipeline 33326. `warning_due` itself has its own test.)
        let warned = WARNED.lock().unwrap_or_else(|e| e.into_inner());
        let key = ("warn-throttle".to_owned(), InspectionLimit::Args.reason());
        let (_, held) = warned
            .as_ref()
            .and_then(|log| log.get(&key))
            .copied()
            .unwrap();
        assert_eq!(held, 49);
    }

    /// A refused request is decided — blocking mode refuses it, learning mode
    /// records it — and an ML score could change neither, since
    /// `apply_verdict` returns on a Block; while what ML reads is not bounded
    /// by the limits (307 ms on a 9.9 MiB form the rules refused in 12 ms).
    #[test]
    fn ml_is_not_run_on_a_request_the_engine_refused() {
        let policy = serde_json::json!({"max_inspected_args": 3, "ml": {"enable": true}});
        for mode in [WafMode::Blocking, WafMode::Learning] {
            let s = site(mode.clone(), policy.clone());
            let past = body_phase(&s, "/f", "a=v&b=v&c=v&d=v");
            assert!(
                past.rule_matches
                    .iter()
                    .any(|m| m.rule_id == InspectionLimit::Args.rule_id()),
                "{mode:?}"
            );
            assert!(
                past.ml_scores.is_empty(),
                "{mode:?}: ML scored a refused request: {:?}",
                past.ml_scores
            );
            let within = body_phase(&s, "/f", "a=v&b=v&c=last-value");
            assert!(
                within.ml_scores.contains_key("combined"),
                "{mode:?}: ML must still score what was inspected"
            );
        }
    }

    /// The legitimate traffic that meets a limit, named in the advice so an
    /// operator can tell it from a request built to be expensive.
    #[test]
    fn the_remediation_names_the_legitimate_shapes_that_reach_a_limit() {
        let ctx = refused(Phase::RequestBody);
        let text = remediation(InspectionLimit::ArgBytes, &ctx, "shop");
        for shape in [
            "base64 inside JSON or XML",
            "text/plain",
            "multipart/related",
            "NDJSON sent as application/json",
        ] {
            assert!(text.contains(shape), "{shape}: {text}");
        }
        let text = remediation(InspectionLimit::Args, &ctx, "shop");
        assert!(text.contains("thousands of fields"), "{text}");
    }

    #[test]
    fn the_remediation_names_the_setting_and_its_value() {
        let ctx = refused(Phase::RequestBody);
        let text = remediation(InspectionLimit::ArgBytes, &ctx, "shop");
        assert!(
            text.contains("max_inspected_arg_bytes (now 1048576 bytes)"),
            "{text}"
        );
        assert!(text.contains("site 'shop'"), "{text}");
        let text = remediation(InspectionLimit::Time, &ctx, "shop");
        assert!(
            text.contains("inspection_time_budget_ms (now 1000 ms)"),
            "{text}"
        );
    }

    /// One WARN per site and limit every `WARN_EVERY`, counting the ones it
    /// held back in between; each site and limit on its own.
    #[test]
    fn a_held_back_warning_is_counted_on_the_next_one() {
        let mut log = WarnLog::new();
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let (args, bytes) = (InspectionLimit::Args, InspectionLimit::ArgBytes);
        assert_eq!(warning_due(&mut log, "a", args, at(0)), Some(0));
        assert_eq!(warning_due(&mut log, "a", args, at(1)), None);
        assert_eq!(warning_due(&mut log, "a", args, at(9)), None);
        assert_eq!(warning_due(&mut log, "a", bytes, at(9)), Some(0));
        assert_eq!(warning_due(&mut log, "b", args, at(9)), Some(0));
        assert_eq!(warning_due(&mut log, "a", args, at(10)), Some(2));
        assert_eq!(warning_due(&mut log, "a", args, at(11)), None);
        assert_eq!(warning_due(&mut log, "a", args, at(25)), Some(1));
    }
}
