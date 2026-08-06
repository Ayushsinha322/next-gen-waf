//! SSRF detection: URLs whose host designates an internal or cloud-metadata target.
//!
//! # Why this exists
//!
//! The CRS importer compiles `@rbl`, `@ipMatch`, `@ipMatchF` and `@geoLookup` to
//! [`Operator::Never`](crate::dsl::ast::Operator::Never) — the rules that use them are
//! loaded but can never fire. That silently removed SSRF coverage: nothing inspected a
//! URL's host to notice it pointed at `127.0.0.1`, a private range, or the cloud
//! metadata endpoint. A request could ask the application to fetch
//! `http://169.254.169.254/latest/meta-data/iam/security-credentials/` and no rule
//! objected.
//!
//! # Why a native operator rather than regexes
//!
//! Because the interesting part of SSRF is *encoding*, and a regex over the raw text
//! has to enumerate encodings it cannot know in advance. `169.254.169.254` is also
//! `2852039166`, `0xA9FEA9FE`, `0251.0376.0251.0376`, `0xa9.0xfe.0xa9.0xfe`,
//! `::ffff:169.254.169.254` and more — all of which the network stack will happily
//! dial. Parsing the host into an actual [`IpAddr`] and then asking whether that
//! address is internal covers every spelling of the same destination, including ones
//! nobody wrote a pattern for.
//!
//! # False-positive control
//!
//! Host parsing is applied ONLY to the authority component of something that looks
//! like `scheme://host`. A bare `2852039166` in a parameter is a number, not an SSRF
//! attempt, and treating it as one would generate noise on order IDs, timestamps and
//! hashes. The cost of that decision is stated in [`contains_ssrf_url`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Cloud metadata hostnames. These resolve to link-local addresses that the IP checks
/// below already cover, but the *name* is what appears in a payload when the attacker
/// does not want to write an address, so it is matched literally too.
const METADATA_HOSTS: &[&str] = &[
    "metadata.google.internal",
    "metadata.goog",
    // AWS/GCP/Azure/Oracle all use 169.254.169.254; Alibaba uses 100.100.100.200.
    "instance-data",
    "metadata",
    // Kubernetes / Docker internal service discovery names commonly abused to reach
    // the API server or a sidecar from a request-driven fetch.
    "kubernetes.default.svc",
    "kubernetes.default",
];

/// Returns true if `ip` designates something a server-side fetch should never be
/// pointed at by untrusted input.
pub fn is_internal_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_internal_v4(v4),
        IpAddr::V6(v6) => {
            // ORDER MATTERS. The native-IPv6 checks must run FIRST, because
            // Ipv6Addr::to_ipv4() also converts IPv4-*compatible* addresses — anything
            // with the top 96 bits zero — and that includes ::1 and ::. So ::1 would
            // convert to 0.0.0.1, which is not internal by the IPv4 rules, and IPv6
            // loopback would be judged public. Checking is_internal_v6 first avoids
            // that whole class of misjudgement.
            if is_internal_v6(v6) {
                return true;
            }
            // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d) addresses
            // reach IPv4 destinations, so they must be judged as the IPv4 address they
            // carry — otherwise ::ffff:127.0.0.1 would sail past a v4-only check.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_internal_v4(&v4);
            }
            if let Some(v4) = v6.to_ipv4() {
                return is_internal_v4(&v4);
            }
            false
        }
    }
}

fn is_internal_v4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()            // 127/8
        || ip.is_private()      // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()   // 169.254/16 — the cloud metadata range
        || ip.is_unspecified()  // 0.0.0.0 — routes to localhost on many stacks
        || ip.is_broadcast()
        || ip.is_multicast()
        || o[0] == 100 && (64..=127).contains(&o[1])   // 100.64/10 carrier-grade NAT
        || o[0] == 192 && o[1] == 0 && o[2] == 0       // 192.0.0/24 IETF protocol assignments
        || o[0] == 198 && (18..=19).contains(&o[1])    // 198.18/15 benchmarking
        || o[0] == 127 // belt and braces for 127/8
}

fn is_internal_v6(ip: &Ipv6Addr) -> bool {
    let seg = ip.segments();
    ip.is_loopback()                       // ::1
        || ip.is_unspecified()             // ::
        || ip.is_multicast()
        || (seg[0] & 0xfe00) == 0xfc00     // fc00::/7 unique local
        || (seg[0] & 0xffc0) == 0xfe80     // fe80::/10 link local
        // fd00:ec2::254 — the AWS IPv6 metadata endpoint, inside fc00::/7 above but
        // called out because it is the one that matters in practice.
        || (seg[0] == 0xfd00 && seg[1] == 0x0ec2)
}

/// Parse a URL host component into an address, accepting every encoding a network
/// stack will accept — not just dotted-quad.
///
/// Handles: dotted quad, bare decimal (`2852039166`), hex (`0xA9FEA9FE` and
/// `0xa9.0xfe.0xa9.0xfe`), octal (`0251.0376.0251.0376`), short forms (`127.1`,
/// `169.254.43518`), bracketed and unbracketed IPv6, and IPv4-mapped IPv6.
///
/// Returns `None` for anything that is a genuine hostname — resolving those is a DNS
/// question, deliberately out of scope here (see the module docs).
pub fn parse_host_to_ip(host: &str) -> Option<IpAddr> {
    let h = host.trim();
    if h.is_empty() {
        return None;
    }

    // Bracketed IPv6: [::1], [::ffff:127.0.0.1]
    if let Some(inner) = h.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }

    // Plain forms the standard parser already accepts (dotted quad, full IPv6).
    if let Ok(ip) = h.parse::<IpAddr>() {
        return Some(ip);
    }

    // IPv6 with a zone id (fe80::1%eth0) — judge the address, ignore the zone.
    if let Some((addr, _zone)) = h.split_once('%') {
        if let Ok(v6) = addr.parse::<Ipv6Addr>() {
            return Some(IpAddr::V6(v6));
        }
    }

    parse_numeric_v4(h).map(IpAddr::V4)
}

/// Parse the numeric IPv4 spellings `inet_aton` accepts and `str::parse` does not.
///
/// `inet_aton` semantics: 1–4 dot-separated parts, each decimal / octal (leading `0`)
/// / hex (`0x`), where the LAST part absorbs all remaining low-order bytes. So `127.1`
/// is 127.0.0.1 and `2852039166` is 169.254.169.254.
fn parse_numeric_v4(host: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }

    let mut vals: Vec<u64> = Vec::with_capacity(parts.len());
    for p in &parts {
        vals.push(parse_int_any_radix(p)?);
    }

    // Every part except the last must fit in one octet.
    let (last, leading) = vals.split_last()?;
    if leading.iter().any(|v| *v > 0xff) {
        return None;
    }
    // The final part absorbs the remaining bytes, so its ceiling depends on how many
    // parts preceded it.
    let remaining_bytes = 4 - leading.len() as u32;
    let max_last: u64 = if remaining_bytes >= 4 {
        u32::MAX as u64
    } else {
        (1u64 << (8 * remaining_bytes)) - 1
    };
    if *last > max_last {
        return None;
    }

    let mut addr: u32 = 0;
    for (i, v) in leading.iter().enumerate() {
        addr |= (*v as u32) << (8 * (3 - i as u32));
    }
    addr |= *last as u32;
    Some(Ipv4Addr::from(addr))
}

/// Parse one host part as hex (`0x..`), octal (leading `0`), or decimal — matching
/// what `inet_aton` accepts, which is what the OS will actually dial.
fn parse_int_any_radix(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    if let Some(hex) = lower.strip_prefix("0x") {
        if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        return u64::from_str_radix(hex, 16).ok();
    }
    if lower.len() > 1 && lower.starts_with('0') {
        if !lower[1..].chars().all(|c| ('0'..='7').contains(&c)) {
            return None;
        }
        return u64::from_str_radix(&lower[1..], 8).ok();
    }
    if !lower.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    lower.parse::<u64>().ok()
}

/// Strip credentials, port and trailing dots from a URL authority, yielding the host.
///
/// `http://expected.com@169.254.169.254/` is the classic confusion trick: everything
/// before `@` is userinfo, so the real destination is the metadata endpoint. Taking the
/// text after the LAST `@` is what the URL parser does, and therefore what must be
/// judged.
fn host_from_authority(authority: &str) -> &str {
    let after_userinfo = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    // IPv6 literals keep their brackets; only strip a port after the closing bracket.
    if after_userinfo.starts_with('[') {
        if let Some(end) = after_userinfo.find(']') {
            return &after_userinfo[..=end];
        }
        return after_userinfo;
    }
    // Port stripping must not mangle an UNBRACKETED IPv6 literal. RFC 3986 requires
    // brackets, but attackers do not read RFCs and the OS resolver accepts
    // `::ffff:169.254.169.254` bare — naively taking everything before the last colon
    // turns that into `::ffff`, which is not internal, and the payload walks through.
    //
    // A host:port authority has exactly one colon; an IPv6 literal has two or more.
    let host = if after_userinfo.matches(':').count() > 1 {
        after_userinfo // unbracketed IPv6 literal — there is no port to strip
    } else {
        match after_userinfo.rfind(':') {
            Some(i) => &after_userinfo[..i],
            None => after_userinfo,
        }
    };
    // "127.0.0.1." is a valid FQDN spelling of the same address.
    host.trim_end_matches('.')
}

/// True if `value` contains a URL pointing at an internal or metadata destination.
///
/// SCOPE, stated plainly: this decides on the URL's literal host. It does not resolve
/// hostnames, so `http://evil.test/` whose DNS answers `127.0.0.1` (DNS rebinding) is
/// NOT caught here. Resolving names during rule evaluation would put an unbounded
/// network round-trip on the request path, and the rule VM is synchronous — a
/// rebinding tier belongs in the async pipeline with its own cache, not here. What this
/// does cover is every *encoding* of a literal internal address, which is the form the
/// overwhelming majority of SSRF payloads take.
pub fn contains_ssrf_url(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let mut search = lower.as_str();

    while let Some(pos) = search.find("://") {
        // Require a plausible scheme immediately before "://" so random text
        // containing "://" is not treated as a URL.
        let scheme: String = search[..pos]
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
            .collect();
        let scheme_ok = scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic());

        let after = &search[pos + 3..];
        let authority_end = after
            .find(['/', '?', '#', '\\', ' ', '\t', '"', '\'', ',', ')', '>'])
            .unwrap_or(after.len());
        let authority = &after[..authority_end];

        if scheme_ok && !authority.is_empty() {
            let host = host_from_authority(authority);
            if !host.is_empty() {
                if METADATA_HOSTS.contains(&host) {
                    return true;
                }
                if let Some(ip) = parse_host_to_ip(host) {
                    if is_internal_ip(&ip) {
                        return true;
                    }
                }
            }
        }

        search = &after[authority_end.min(after.len())..];
        if search.is_empty() {
            break;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The audit's acceptance criterion: every encoding of the metadata endpoint must
    /// fire. Each of these is a spelling the OS resolver accepts, so each is a real
    /// route to 169.254.169.254.
    #[test]
    fn every_encoding_of_the_metadata_endpoint_is_detected() {
        let encodings = [
            "169.254.169.254",        // dotted quad
            "2852039166",             // bare decimal
            "0xA9FEA9FE",             // hex dword
            "0xa9.0xfe.0xa9.0xfe",    // dotted hex
            "0251.0376.0251.0376",    // dotted octal
            "169.254.43518",          // 3-part short form
            "169.16689150",           // 2-part short form
            "::ffff:169.254.169.254", // IPv4-mapped IPv6
        ];
        for enc in encodings {
            let url = format!("http://{enc}/latest/meta-data/iam/security-credentials/");
            assert!(
                contains_ssrf_url(&url),
                "encoding {enc} of the metadata endpoint was NOT detected"
            );
        }
    }

    #[test]
    fn loopback_encodings_are_detected() {
        for enc in [
            "127.0.0.1",
            "127.1",
            "127.0.1",
            "2130706433",
            "0x7f000001",
            "0177.0.0.1",
            "0x7f.1",
            "[::1]",
            "[::ffff:127.0.0.1]",
        ] {
            assert!(
                contains_ssrf_url(&format!("http://{enc}/admin")),
                "loopback encoding {enc} was NOT detected"
            );
        }
    }

    #[test]
    fn private_and_link_local_ranges_are_detected() {
        for host in [
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "100.64.0.1",
            "[fd00::1]",
            "[fe80::1]",
            "[fd00:ec2::254]",
        ] {
            assert!(
                contains_ssrf_url(&format!("https://{host}/")),
                "internal host {host} was NOT detected"
            );
        }
    }

    /// The other half of the requirement: public URLs must NOT fire. A detector that
    /// flags ordinary outbound URLs is unusable regardless of its recall.
    #[test]
    fn public_urls_are_not_flagged() {
        for url in [
            "https://example.com/callback",
            "http://93.184.216.34/", // example.com's public address
            "https://api.github.com/repos/x/y",
            "https://8.8.8.8/resolve",
            "http://172.32.0.1/",         // just outside 172.16/12
            "http://11.0.0.1/",           // just outside 10/8
            "http://100.128.0.1/",        // just outside 100.64/10
            "https://[2606:4700::1111]/", // public IPv6
            "http://169.253.169.254/",    // one off from link-local
            "http://170.254.169.254/",    // one off the other way
        ] {
            assert!(
                !contains_ssrf_url(url),
                "public URL {url} was WRONGLY flagged"
            );
        }
    }

    /// Userinfo confusion: everything before the last '@' is credentials, so the real
    /// destination is the metadata endpoint.
    #[test]
    fn userinfo_confusion_is_resolved_to_the_real_host() {
        for url in [
            "http://expected.com@169.254.169.254/",
            "http://user:pass@127.0.0.1:8080/admin",
            "http://a@b@10.0.0.1/",
        ] {
            assert!(contains_ssrf_url(url), "userinfo trick not resolved: {url}");
        }
        // ...and the inverse must not over-trigger: an internal-looking USERINFO with a
        // public host is not SSRF.
        assert!(!contains_ssrf_url("http://127.0.0.1@example.com/"));
    }

    #[test]
    fn ports_trailing_dots_and_case_are_handled() {
        assert!(contains_ssrf_url("http://127.0.0.1:8080/"));
        assert!(contains_ssrf_url("http://127.0.0.1./"));
        assert!(contains_ssrf_url("HTTP://169.254.169.254/"));
        assert!(contains_ssrf_url("gopher://127.0.0.1:6379/_INFO"));
    }

    #[test]
    fn metadata_hostnames_are_matched_by_name() {
        assert!(contains_ssrf_url(
            "http://metadata.google.internal/computeMetadata/v1/"
        ));
        assert!(contains_ssrf_url(
            "http://kubernetes.default.svc/api/v1/secrets"
        ));
        assert!(!contains_ssrf_url("http://metadata.example.com/"));
    }

    #[test]
    fn urls_embedded_in_larger_values_are_found() {
        assert!(contains_ssrf_url(
            "url=http://169.254.169.254/latest&next=2"
        ));
        assert!(contains_ssrf_url(
            "{\"webhook\":\"http://127.0.0.1:9200/_cat\"}"
        ));
        // Multiple URLs: a benign one first must not stop the scan.
        assert!(contains_ssrf_url(
            "a=https://example.com/x b=http://10.1.2.3/y"
        ));
    }

    #[test]
    fn non_urls_and_bare_numbers_are_ignored() {
        // The FP-control decision: a bare number is a number, not a destination.
        assert!(!contains_ssrf_url("2852039166"));
        assert!(!contains_ssrf_url("order_id=2130706433"));
        assert!(!contains_ssrf_url("just some text with :// in it"));
        assert!(!contains_ssrf_url(""));
        assert!(!contains_ssrf_url("127.0.0.1"));
    }

    #[test]
    fn inet_aton_parser_rejects_out_of_range_and_malformed() {
        assert_eq!(parse_host_to_ip("256.1.1.1"), None);
        assert_eq!(parse_host_to_ip("1.2.3.4.5"), None);
        assert_eq!(parse_host_to_ip("0x"), None);
        assert_eq!(parse_host_to_ip("08"), None, "8 is not a valid octal digit");
        assert_eq!(parse_host_to_ip("4294967296"), None, "exceeds u32");
        assert_eq!(parse_host_to_ip("example.com"), None);
        assert_eq!(parse_host_to_ip(""), None);
    }

    #[test]
    fn numeric_parser_agrees_with_dotted_quad() {
        assert_eq!(
            parse_host_to_ip("2852039166"),
            parse_host_to_ip("169.254.169.254")
        );
        assert_eq!(
            parse_host_to_ip("0x7f000001"),
            parse_host_to_ip("127.0.0.1")
        );
        assert_eq!(parse_host_to_ip("127.1"), parse_host_to_ip("127.0.0.1"));
    }
}
