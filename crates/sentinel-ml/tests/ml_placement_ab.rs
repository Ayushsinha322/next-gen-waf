//! Offline A/B for ML candidate selection — run manually:
//!   cargo test -p sentinel-ml --test ml_placement_ab -- --ignored --nocapture
use std::net::{IpAddr, Ipv4Addr};

fn lines(path: &str, every: usize, cap: usize) -> Vec<String> {
    let Ok(t) = std::fs::read_to_string(path) else {
        return vec![];
    };
    t.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .step_by(every.max(1))
        .take(cap)
        .map(str::to_owned)
        .collect()
}

fn ctx(
    uri: &str,
    ct: Option<&str>,
    body: Option<String>,
) -> sentinel_core::context::RequestContext {
    let mut c =
        sentinel_core::context::RequestContext::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 0);
    c.uri = uri.parse().unwrap_or_else(|_| "/".parse().unwrap());
    if let Some(ct) = ct {
        c.request_headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_str(ct).unwrap(),
        );
    }
    c.request_body = body.map(bytes::Bytes::from);
    c
}

type Placement = Box<dyn Fn(&str) -> sentinel_core::context::RequestContext>;

fn enc(v: &str) -> String {
    percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC).to_string()
}

#[test]
#[ignore]
fn compare() {
    let home = std::env::var("HOME").unwrap();
    let corp = format!("{home}/waf-ml-corpora");
    let mut attacks = Vec::new();
    for e in std::fs::read_dir(format!("{corp}/evasion-corpus"))
        .unwrap()
        .flatten()
    {
        attacks.extend(lines(e.path().to_str().unwrap(), 20, 400));
    }
    let mut hard = Vec::new();
    for e in std::fs::read_dir(format!("{corp}/hard-benign"))
        .unwrap()
        .flatten()
    {
        hard.extend(lines(e.path().to_str().unwrap(), 1, 400));
    }
    let good = lines(&format!("{corp}/benign-corpus/good_fwaf.txt"), 250, 5000);
    let words = [
        "whoami", "users", "profile", "api", "v1", "login", "admin", "orders", "basket", "search",
        "products", "static", "images", "assets", "health", "status", "me", "account", "settings",
        "id",
    ];
    let eng = sentinel_ml::MlEngine::new(64, 1_000_000, None);
    let flag =
        |c: &sentinel_core::context::RequestContext| eng.evaluate(c).payload_attack_score >= 0.9;
    let rate = |n: usize, d: usize| {
        if d == 0 {
            0.0
        } else {
            100.0 * n as f64 / d as f64
        }
    };

    let placements: Vec<(&str, Placement)> = vec![
        (
            "query",
            Box::new(|v| ctx(&format!("/search?q={}", enc(v)), None, None)),
        ),
        (
            "json field",
            Box::new(|v| {
                ctx(
                    "/api/x",
                    Some("application/json"),
                    Some(serde_json::json!({"q": v}).to_string()),
                )
            }),
        ),
        (
            "json nested",
            Box::new(|v| {
                ctx(
                    "/api/BasketItems",
                    Some("application/json"),
                    Some(
                        serde_json::json!({"items":[{"id":1,"qty":2},{"id":5,"qty":1}],"note": v})
                            .to_string(),
                    ),
                )
            }),
        ),
        (
            "form field",
            Box::new(|v| {
                ctx(
                    "/login",
                    Some("application/x-www-form-urlencoded"),
                    Some(format!("user=a&q={}", enc(v))),
                )
            }),
        ),
    ];
    println!(
        "\nsample: attacks={} hard-benign={} benign-urls={}",
        attacks.len(),
        hard.len(),
        good.len()
    );
    println!(
        "{:<12} {:>10} {:>12}",
        "placement", "attack%", "hard-benign%"
    );
    for (name, mk) in &placements {
        let a = attacks.iter().filter(|v| flag(&mk(v))).count();
        let h = hard.iter().filter(|v| flag(&mk(v))).count();
        println!(
            "{:<12} {:>9.2}% {:>11.2}%",
            name,
            rate(a, attacks.len()),
            rate(h, hard.len())
        );
    }
    let g = good.iter().filter(|u| flag(&ctx(u, None, None))).count();
    println!(
        "{:<12} {:>10} {:>11.2}%  (benign request lines as URIs)",
        "uri",
        "-",
        rate(g, good.len())
    );
    let w = words
        .iter()
        .filter(|s| flag(&ctx(&format!("/rest/user/{s}"), None, None)))
        .count();
    println!(
        "{:<12} {:>10} {:>11}  (plain path words flagged of {})",
        "path words",
        "-",
        w,
        words.len()
    );
    let ap = attacks
        .iter()
        .filter(|v| flag(&ctx(&format!("/p/{}", enc(v)), None, None)))
        .count();
    println!(
        "{:<12} {:>9.2}%  (attack as an encoded path segment)",
        "path attack",
        rate(ap, attacks.len())
    );
}
