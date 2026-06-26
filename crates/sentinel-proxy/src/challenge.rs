//! Native browser challenge — stateless Proof-of-Work (no third party, on-prem).
//!
//! When the WAF decides a client must prove it's a real browser, it serves a
//! lightweight interstitial that makes the browser compute a small hashcash-style
//! proof. The challenge and the resulting "clearance" are both **stateless**:
//! they are HMAC-signed tokens, so no server-side session store is needed and
//! any node in a cluster can verify a token issued by another (share the secret
//! via `SENTINEL_CHALLENGE_SECRET`).
//!
//! Flow:
//!   1. No clearance + no proof  → serve interstitial (embeds nonce/ts/diff/sig).
//!   2. Browser solves PoW, sets `sentinel_pow` cookie, reloads.
//!   3. Proof verifies → issue `sentinel_clear` cookie (HMAC of ip|exp), 302 back.
//!   4. Clearance cookie present + valid → request passes (no re-challenge).

use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use http::{header, HeaderMap, Uri};
use ring::{hmac, rand::{SecureRandom, SystemRandom}};

/// PoW difficulty in leading zero **bits** of SHA-256(nonce "." solution).
/// 17 bits ≈ ~131k expected hashes ≈ a few hundred ms in-browser once per TTL —
/// negligible for a human, expensive for a bot doing it on every request.
const DIFFICULTY_BITS: u32 = 17;
/// How long an issued challenge stays solvable.
const CHALLENGE_TTL_SECS: u64 = 300;
/// How long a granted clearance lasts before re-challenge.
const CLEARANCE_TTL_SECS: u64 = 1800;

const POW_COOKIE: &str = "sentinel_pow";
const CLEAR_COOKIE: &str = "sentinel_clear";

/// What the request handler should do for a Challenge decision.
pub enum Outcome {
    /// Client already holds a valid clearance cookie — let the request through
    /// without re-challenging.
    Pass,
    /// Proof verified — set a clearance cookie and redirect back to `location`.
    Grant { location: String, set_cookie: String, expire_pow: String },
    /// Serve the interstitial challenge page.
    Serve { html: String },
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn key() -> &'static hmac::Key {
    static KEY: OnceLock<hmac::Key> = OnceLock::new();
    KEY.get_or_init(|| {
        let bytes = match std::env::var("SENTINEL_CHALLENGE_SECRET") {
            Ok(s) if !s.is_empty() => s.into_bytes(),
            _ => {
                let mut b = [0u8; 32];
                // Random per-process secret when unset (single-node default).
                let _ = SystemRandom::new().fill(&mut b);
                b.to_vec()
            }
        };
        hmac::Key::new(hmac::HMAC_SHA256, &bytes)
    })
}

fn sign(parts: &[&str]) -> String {
    let msg = parts.join("|");
    hex::encode(hmac::sign(key(), msg.as_bytes()).as_ref())
}

/// Constant-time byte-slice equality (length-independent on match path).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn sig_ok(parts: &[&str], sig_hex: &str) -> bool {
    let expected = sign(parts);
    ct_eq(expected.as_bytes(), sig_hex.as_bytes())
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let p = part.trim();
        if let Some(v) = p.strip_prefix(name).and_then(|r| r.strip_prefix('=')) {
            return Some(v.to_string());
        }
    }
    None
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut c = 0u32;
    for b in bytes {
        if *b == 0 {
            c += 8;
        } else {
            c += b.leading_zeros();
            break;
        }
    }
    c
}

/// Is there a valid, unexpired clearance cookie bound to this client IP?
pub fn clearance_valid(headers: &HeaderMap, ip: IpAddr) -> bool {
    let Some(val) = cookie(headers, CLEAR_COOKIE) else { return false };
    let mut it = val.splitn(2, '.');
    let (Some(exp_s), Some(sig)) = (it.next(), it.next()) else { return false };
    let Ok(exp) = exp_s.parse::<u64>() else { return false };
    if exp < now() {
        return false;
    }
    sig_ok(&[&ip.to_string(), exp_s], sig)
}

/// Verify a submitted Proof-of-Work cookie: `nonce.ts.diff.sig.solution`.
fn pow_valid(headers: &HeaderMap) -> bool {
    let Some(val) = cookie(headers, POW_COOKIE) else { return false };
    let parts: Vec<&str> = val.split('.').collect();
    if parts.len() != 5 {
        return false;
    }
    let (nonce, ts_s, diff_s, sig, solution) = (parts[0], parts[1], parts[2], parts[3], parts[4]);
    // 1. signature binds nonce+ts+diff (so the client can't forge an easy challenge)
    if !sig_ok(&[nonce, ts_s, diff_s], sig) {
        return false;
    }
    // 2. freshness
    let Ok(ts) = ts_s.parse::<u64>() else { return false };
    let n = now();
    if ts > n + 5 || n.saturating_sub(ts) > CHALLENGE_TTL_SECS {
        return false;
    }
    // 3. the actual work: SHA-256(nonce "." solution) must have `diff` leading zero bits
    let Ok(diff) = diff_s.parse::<u32>() else { return false };
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(nonce.as_bytes());
    h.update(b".");
    h.update(solution.as_bytes());
    leading_zero_bits(&h.finalize()) >= diff
}

fn make_clearance_cookie(ip: IpAddr) -> String {
    let exp = now() + CLEARANCE_TTL_SECS;
    let exp_s = exp.to_string();
    let sig = sign(&[&ip.to_string(), &exp_s]);
    format!(
        "{CLEAR_COOKIE}={exp_s}.{sig}; Path=/; Max-Age={CLEARANCE_TTL_SECS}; HttpOnly; SameSite=Lax"
    )
}

/// Resolve a Challenge decision into a concrete action.
///
/// This is the single point every challenge source funnels through (suspicious
/// bot, CRS rule, WASM plugin), so the clearance check lives here — a client
/// that already solved a PoW within the clearance TTL is never re-challenged,
/// regardless of which subsystem requested the challenge.
pub fn resolve(headers: &HeaderMap, ip: IpAddr, uri: &Uri) -> Outcome {
    if clearance_valid(headers, ip) {
        return Outcome::Pass;
    }
    if pow_valid(headers) {
        // Proof accepted — grant clearance and bounce back to the original URL.
        let location = uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".to_string());
        return Outcome::Grant {
            location,
            set_cookie: make_clearance_cookie(ip),
            expire_pow: format!("{POW_COOKIE}=; Path=/; Max-Age=0"),
        };
    }
    Outcome::Serve { html: interstitial() }
}

/// Build the interstitial HTML embedding a fresh, signed challenge.
fn interstitial() -> String {
    let mut nonce_bytes = [0u8; 8];
    let _ = SystemRandom::new().fill(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);
    let ts = now().to_string();
    let diff = DIFFICULTY_BITS.to_string();
    let sig = sign(&[&nonce, &ts, &diff]);

    // The PoW cookie must outlive the server's accept window, or a slow device
    // loses it before submitting a still-valid solution. Drive the cookie's
    // max-age from CHALLENGE_TTL_SECS so the two can't drift apart.
    let head = format!(
        r#"<script>window.SENTINEL_CH={{nonce:"{nonce}",ts:{ts},diff:{diff},sig:"{sig}",maxage:{CHALLENGE_TTL_SECS}}};</script>"#
    );
    format!("{HTML_HEAD}{head}{HTML_BODY}{SOLVER_JS}{HTML_TAIL}")
}

const HTML_HEAD: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Checking your browser…</title><style>
:root{color-scheme:dark}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#070b12;color:#e6edf3;font-family:system-ui,Segoe UI,Roboto,sans-serif}
.card{max-width:440px;padding:40px 36px;text-align:center;background:#0d1420;border:1px solid rgba(0,212,255,.18);border-radius:16px;box-shadow:0 24px 70px rgba(0,0,0,.5)}
.logo{font-weight:800;letter-spacing:1px;font-size:13px;color:#22d3ee;text-transform:uppercase}
h1{font-size:19px;margin:14px 0 6px}p{font-size:13px;color:#8b97a7;line-height:1.6;margin:0}
.spin{width:46px;height:46px;margin:22px auto 6px;border:3px solid rgba(34,211,238,.15);border-top-color:#22d3ee;border-radius:50%;animation:s 1s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}.bar{height:5px;background:rgba(255,255,255,.06);border-radius:3px;margin-top:18px;overflow:hidden}
.bar > i{display:block;height:100%;width:0;background:linear-gradient(90deg,#22d3ee,#0d9488);transition:width .2s}
.foot{margin-top:18px;font-size:10px;color:#52525b}</style></head>"#;

const HTML_BODY: &str = r#"<body><div class="card"><div class="logo">Sentinel WAF</div><div class="spin"></div><h1>Checking your browser</h1><p id="msg">Verifying you are human — this runs entirely in your browser and takes a moment.</p><div class="bar"><i id="pb"></i></div><div class="foot">No tracking · no third-party · Proof-of-Work</div></div>"#;

// Synchronous SHA-256 (FIPS 180-4) over an ASCII string + the PoW solver loop.
const SOLVER_JS: &str = r#"<script>
(function(){
var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function rotr(x,n){return (x>>>n)|(x<<(32-n));}
function sha256(ascii){
  var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  var bytes=[],i;for(i=0;i<ascii.length;i++)bytes.push(ascii.charCodeAt(i)&0xff);
  var l=bytes.length;bytes.push(0x80);while((bytes.length%64)!==56)bytes.push(0);
  var bl=l*8;for(i=7;i>=0;i--)bytes.push((bl/Math.pow(2,8*i))&0xff);
  var w=new Array(64);
  for(var off=0;off<bytes.length;off+=64){
    for(i=0;i<16;i++)w[i]=(bytes[off+i*4]<<24)|(bytes[off+i*4+1]<<16)|(bytes[off+i*4+2]<<8)|(bytes[off+i*4+3]);
    for(i=16;i<64;i++){var s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>>3);var s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>>10);w[i]=(w[i-16]+s0+w[i-7]+s1)|0;}
    var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for(i=0;i<64;i++){var S1=rotr(e,6)^rotr(e,11)^rotr(e,25);var ch=(e&f)^((~e)&g);var t1=(h+S1+ch+K[i]+w[i])|0;var S0=rotr(a,2)^rotr(a,13)^rotr(a,22);var mj=(a&b)^(a&c)^(b&c);var t2=(S0+mj)|0;h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;}
    H[0]=(H[0]+a)|0;H[1]=(H[1]+b)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0;
  }
  var hex="";for(i=0;i<8;i++){var v=H[i]>>>0;hex+=("00000000"+v.toString(16)).slice(-8);}return hex;
}
function leadOk(hex,diff){var full=diff>>2,rem=diff&3,i;for(i=0;i<full;i++)if(hex[i]!=="0")return false;if(rem){if(parseInt(hex[full],16)>=(1<<(4-rem)))return false;}return true;}
var CH=window.SENTINEL_CH,n=0,pb=document.getElementById("pb");
function step(){
  var end=n+4000;
  for(;n<end;n++){ if(leadOk(sha256(CH.nonce+"."+n),CH.diff)){ document.cookie="sentinel_pow="+CH.nonce+"."+CH.ts+"."+CH.diff+"."+CH.sig+"."+n+"; path=/; max-age="+CH.maxage+"; SameSite=Lax"; location.reload(); return; } }
  if(pb)pb.style.width=((n%200000)/2000)+"%";
  setTimeout(step,0);
}
setTimeout(step,30);
})();
</script>"#;

const HTML_TAIL: &str = r#"</body></html>"#;

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn solve(nonce: &str, diff: u32) -> u64 {
        let mut n = 0u64;
        loop {
            let mut h = Sha256::new();
            h.update(nonce.as_bytes());
            h.update(b".");
            h.update(n.to_string().as_bytes());
            if leading_zero_bits(&h.finalize()) >= diff {
                return n;
            }
            n += 1;
        }
    }

    fn headers_with(cookie: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, cookie.parse().unwrap());
        h
    }

    #[test]
    fn pow_roundtrip_accepts_valid_and_rejects_tampered() {
        let nonce = "0011223344556677";
        let ts = now().to_string();
        let diff = "12";
        let sig = sign(&[nonce, &ts, diff]);
        let sol = solve(nonce, 12);

        let good = format!("{POW_COOKIE}={nonce}.{ts}.{diff}.{sig}.{sol}");
        assert!(pow_valid(&headers_with(&good)), "valid proof must pass");

        // Forged signature (claim an easier challenge) must fail.
        let forged = format!("{POW_COOKIE}={nonce}.{ts}.4.deadbeef.{sol}");
        assert!(!pow_valid(&headers_with(&forged)), "forged sig must fail");

        // Right signature but wrong/insufficient solution must fail.
        let bad_sol = format!("{POW_COOKIE}={nonce}.{ts}.30.{}.1", sign(&[nonce, &ts, "30"]));
        assert!(!pow_valid(&headers_with(&bad_sol)), "insufficient work must fail");
    }

    #[test]
    fn stale_challenge_is_rejected() {
        let nonce = "aabbccddeeff0011";
        let old_ts = (now() - CHALLENGE_TTL_SECS - 10).to_string();
        let diff = "10";
        let sig = sign(&[nonce, &old_ts, diff]);
        let sol = solve(nonce, 10);
        let stale = format!("{POW_COOKIE}={nonce}.{old_ts}.{diff}.{sig}.{sol}");
        assert!(!pow_valid(&headers_with(&stale)), "expired challenge must fail");
    }

    #[test]
    fn resolve_passes_on_valid_clearance_without_rechallenge() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let exp = (now() + 100).to_string();
        let sig = sign(&[&ip.to_string(), &exp]);
        let ck = format!("{CLEAR_COOKIE}={exp}.{sig}");
        let uri: Uri = "/dashboard".parse().unwrap();

        // A rule/plugin can set Challenge even though the client is already
        // cleared; resolve() must let it through rather than serving a new PoW.
        assert!(
            matches!(resolve(&headers_with(&ck), ip, &uri), Outcome::Pass),
            "valid clearance must Pass (no perpetual challenge loop)"
        );

        // No cookies at all → serve the interstitial.
        let empty = HeaderMap::new();
        assert!(
            matches!(resolve(&empty, ip, &uri), Outcome::Serve { .. }),
            "no clearance and no proof must serve the challenge"
        );
    }

    #[test]
    fn clearance_is_ip_bound_and_time_bound() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let exp = (now() + 100).to_string();
        let sig = sign(&[&ip.to_string(), &exp]);
        let ck = format!("{CLEAR_COOKIE}={exp}.{sig}");

        assert!(clearance_valid(&headers_with(&ck), ip), "valid clearance passes");

        let other: IpAddr = "9.9.9.9".parse().unwrap();
        assert!(!clearance_valid(&headers_with(&ck), other), "other IP cannot reuse");

        let past = (now() - 10).to_string();
        let psig = sign(&[&ip.to_string(), &past]);
        let expired = format!("{CLEAR_COOKIE}={past}.{psig}");
        assert!(!clearance_valid(&headers_with(&expired), ip), "expired clearance fails");
    }
}
