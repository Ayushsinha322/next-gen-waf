//! The proxy's side of the rule engine's inspection limits (`InspectionLimits`
//! in sentinel-core): saying so when learning mode forwards a request the
//! engine refused to finish inspecting, and telling the operator what to change.
//!
//! The engine itself records the refusal (a built-in CRITICAL match, a Block
//! and its reason, and the `sentinel_inspection_limit_exceeded_total` count);
//! the site's mode then governs it like any other verdict.

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

/// Called once the site's mode has been applied to `phase`'s verdict. A
/// refused request that learning mode lets through reaches the origin partly
/// uninspected, which is a coverage gap and must not be silent — the same rule
/// the oversize-body path follows for a body it forwards unread.
pub(crate) fn warn_if_forwarded(ctx: &RequestContext, site: &SiteConfig, phase: &Phase) {
    if ctx.decision == WafDecision::Block || !ctx.would_block {
        return;
    }
    if let Some(limit) = refusal_in(ctx, phase) {
        warn!(
            site = %site.id,
            limit = limit.setting(),
            reason = ctx.block_reason.as_deref().unwrap_or(""),
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
    format!(
        "This request went past site '{site}''s inspection limit {setting} (now {now}), so the \
         rule engine stopped rather than judge it on part of its content. If such requests are \
         legitimate, raise {setting} in the site's policy; each increase lets one request cost \
         more inspection time, which is what the limit bounds. A burst of these from one source \
         usually means requests built to be expensive to inspect.",
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
}
