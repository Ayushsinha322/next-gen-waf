//! Edge JWT validation for customer APIs.
//!
//! This module verifies the `Authorization: Bearer <token>` presented by a
//! **client** calling a protected **customer** API. It is deliberately
//! independent of the console/admin authentication used by the management
//! plane — the data plane owns this check and enforces it inline, at the edge,
//! before a request is proxied to the origin.
//!
//! The design goals are:
//!
//!   - **Self-contained** — one entry point, [`validate`], takes a token, a
//!     [`jsonwebtoken::DecodingKey`], and a [`JwtPolicy`], and returns
//!     `Ok(())` (accept) or `Err(reason)` (reject). No global state.
//!   - **Never panics** — every fallible step returns an error string; there
//!     are no `unwrap`/`expect`/indexing panics on attacker-controlled input.
//!   - **Signature + standard claims** — algorithm allow-listing, issuer,
//!     audience, expiry (`exp` is **required**) and not-before (`nbf`) are all
//!     enforced by [`jsonwebtoken`].
//!   - **Scope enforcement** — after the token verifies, every scope in
//!     [`JwtPolicy::required_scopes`] must be present. The scope claim is read
//!     from [`JwtPolicy::scope_claim`] and accepted in either the OAuth2
//!     space-delimited **string** form (`"read write"`) or the **array** form
//!     (`["read","write"]`).
//!
//! Key material can be supplied three ways, all producing a
//! [`jsonwebtoken::DecodingKey`]:
//!
//!   - a static secret ([`jsonwebtoken::DecodingKey::from_secret`]) for HS*;
//!   - a static PEM public key (`from_rsa_pem` / `from_ec_pem`); or
//!   - a JWKS document fetched from the issuer, parsed by
//!     [`decoding_keys_from_jwks`] into a `kid -> DecodingKey` map. Use
//!     [`token_header`] to read the token's `kid` and select the right key.
//!
//! References:
//!   - RFC 7519 (JWT), RFC 7515 (JWS), RFC 7517 (JWK / JWKS)
//!   - RFC 8725 (JWT Best Current Practices) — always allow-list algorithms
//!   - RFC 6749 §3.3 (OAuth2 `scope` — space-delimited)

use std::collections::HashMap;

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

/// Policy describing what a valid token must satisfy for a given site/route.
///
/// Construct directly, or start from [`JwtPolicy::default`] (which sets
/// `scope_claim` to `"scope"` and leaves everything else empty/unset) and
/// override the fields you need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtPolicy {
    /// Allowed signing algorithms, e.g. `["RS256","ES256","HS256"]`. Each entry
    /// is mapped to a [`jsonwebtoken::Algorithm`]; an unknown name makes
    /// [`validate`] reject with an error. Must be non-empty.
    pub algorithms: Vec<String>,
    /// Expected `iss` claim. When `Some`, the token's issuer must match **and
    /// the claim must be present** (a token omitting `iss` is rejected).
    pub issuer: Option<String>,
    /// Expected `aud` claim. When `Some`, the token's audience must match **and
    /// the claim must be present** (a token omitting `aud` is rejected).
    pub audience: Option<String>,
    /// Scopes that must **all** be present on the token. Empty = no scope check.
    pub required_scopes: Vec<String>,
    /// Claim holding the token's scopes. Defaults to `"scope"`. Common
    /// alternatives are `"scp"` and `"permissions"`. The value is accepted as
    /// either a space-delimited string or a JSON array of strings.
    pub scope_claim: String,
}

impl Default for JwtPolicy {
    fn default() -> Self {
        Self {
            algorithms: Vec::new(),
            issuer: None,
            audience: None,
            required_scopes: Vec::new(),
            scope_claim: "scope".to_string(),
        }
    }
}

/// Map a JWT `alg` header name (e.g. `"RS256"`) to a [`jsonwebtoken::Algorithm`].
///
/// Returns `None` for names this build does not support. We use an explicit
/// table rather than `Algorithm::from_str` so the accepted set is unambiguous
/// and stable regardless of the dependency's parsing quirks.
fn parse_algorithm(name: &str) -> Option<Algorithm> {
    Some(match name {
        "HS256" => Algorithm::HS256,
        "HS384" => Algorithm::HS384,
        "HS512" => Algorithm::HS512,
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        "PS256" => Algorithm::PS256,
        "PS384" => Algorithm::PS384,
        "PS512" => Algorithm::PS512,
        "EdDSA" => Algorithm::EdDSA,
        _ => return None,
    })
}

/// Canonical string name for a [`jsonwebtoken::Algorithm`] (inverse of
/// [`parse_algorithm`]). Used by [`token_header`].
fn algorithm_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::HS256 => "HS256",
        Algorithm::HS384 => "HS384",
        Algorithm::HS512 => "HS512",
        Algorithm::ES256 => "ES256",
        Algorithm::ES384 => "ES384",
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        Algorithm::PS256 => "PS256",
        Algorithm::PS384 => "PS384",
        Algorithm::PS512 => "PS512",
        Algorithm::EdDSA => "EdDSA",
    }
}

/// Turn a [`jsonwebtoken`] error into a concise, log-safe rejection reason.
fn reason_for(err: &jsonwebtoken::errors::Error) -> String {
    use jsonwebtoken::errors::ErrorKind::*;
    match err.kind() {
        ExpiredSignature => "expired".to_string(),
        ImmatureSignature => "token not yet valid (nbf)".to_string(),
        InvalidSignature => "invalid signature".to_string(),
        InvalidIssuer => "invalid issuer".to_string(),
        InvalidAudience => "invalid audience".to_string(),
        InvalidSubject => "invalid subject".to_string(),
        MissingRequiredClaim(claim) => format!("missing required claim: {claim}"),
        InvalidAlgorithm => "algorithm not allowed".to_string(),
        MissingAlgorithm => "missing algorithm".to_string(),
        InvalidAlgorithmName => "unknown algorithm".to_string(),
        InvalidToken => "malformed token".to_string(),
        InvalidKeyFormat | InvalidRsaKey(_) | InvalidEcdsaKey => "invalid key".to_string(),
        _ => "invalid token".to_string(),
    }
}

/// Read the scopes carried by `claims` under `claim`, accepting both the
/// space-delimited-string form and the JSON-array-of-strings form. Any other
/// shape (or a missing claim) yields an empty list.
fn extract_scopes(claims: &serde_json::Value, claim: &str) -> Vec<String> {
    match claims.get(claim) {
        Some(serde_json::Value::String(s)) => s.split_whitespace().map(str::to_string).collect(),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// Verify a bearer token string against a decoding key and policy.
///
/// `Ok(())` means the token is valid and satisfies the policy; `Err(reason)`
/// means it must be rejected. This function never panics.
///
/// Validation performed, in order:
///   1. Build a [`Validation`] from `policy.algorithms` (each mapped to a
///      [`jsonwebtoken::Algorithm`]; an unknown name is an error).
///   2. Require `exp` and validate it (tokens with no `exp` are rejected);
///      validate `nbf` when present.
///   3. When set, require the token's `iss` / `aud` to match the policy.
///   4. Verify the signature with `key` and decode the claims.
///   5. Enforce that every scope in `policy.required_scopes` is present.
pub fn validate(token: &str, key: &DecodingKey, policy: &JwtPolicy) -> Result<(), String> {
    if policy.algorithms.is_empty() {
        return Err("no algorithms configured".to_string());
    }

    // Map the configured algorithm names; reject on the first unknown one.
    let mut algs = Vec::with_capacity(policy.algorithms.len());
    for name in &policy.algorithms {
        match parse_algorithm(name) {
            Some(a) => algs.push(a),
            None => return Err(format!("unknown algorithm: {name}")),
        }
    }

    // Seed Validation from the first algorithm, then widen to the full set.
    // Validation::new sets validate_exp = true and requires the `exp` claim,
    // so a token with no expiry is rejected.
    let mut validation = Validation::new(algs[0]);
    validation.algorithms = algs;
    validation.validate_exp = true;
    validation.validate_nbf = true;

    // Standard claims that MUST be present. `exp` is always required (a token
    // with no expiry is rejected, not treated as non-expiring). `iss`/`aud` are
    // additionally required whenever the policy pins them: jsonwebtoken only
    // *compares* iss/aud when the token actually carries the claim — an absent
    // iss/aud matches the `(NotPresent, Some(expected)) => {}` arm and would
    // otherwise be accepted, letting a validly-signed but claim-less token slip
    // past issuer/audience enforcement (RFC 8725 §3.1/§3.3). Requiring the claim
    // closes that gap.
    let mut required: Vec<&str> = vec!["exp"];

    match &policy.issuer {
        Some(iss) => {
            validation.set_issuer(&[iss.as_str()]);
            required.push("iss");
        }
        None => validation.iss = None,
    }
    match &policy.audience {
        Some(aud) => {
            validation.set_audience(&[aud.as_str()]);
            required.push("aud");
        }
        // No audience configured: disable audience validation entirely so a
        // token that carries an `aud` claim is not spuriously rejected.
        None => validation.validate_aud = false,
    }

    validation.set_required_spec_claims(&required);

    let data = decode::<serde_json::Value>(token, key, &validation).map_err(|e| reason_for(&e))?;

    // Signature + standard claims are valid; now enforce required scopes.
    if !policy.required_scopes.is_empty() {
        let present = extract_scopes(&data.claims, &policy.scope_claim);
        for req in &policy.required_scopes {
            if !present.iter().any(|s| s == req) {
                return Err(format!("missing scope: {req}"));
            }
        }
    }

    Ok(())
}

/// Parse a JWKS document into a `kid -> DecodingKey` map (RSA and EC keys).
///
/// Keys without a `kid`, and keys this build cannot turn into a
/// [`DecodingKey`] (unsupported type, malformed parameters), are skipped. A
/// document that is not valid JWKS JSON yields an empty map. Never panics.
pub fn decoding_keys_from_jwks(jwks_json: &[u8]) -> HashMap<String, DecodingKey> {
    let mut out = HashMap::new();
    let set: jsonwebtoken::jwk::JwkSet = match serde_json::from_slice(jwks_json) {
        Ok(s) => s,
        Err(_) => return out,
    };
    for jwk in &set.keys {
        let Some(kid) = jwk.common.key_id.clone() else {
            continue;
        };
        if let Ok(key) = DecodingKey::from_jwk(jwk) {
            out.insert(kid, key);
        }
    }
    out
}

/// Extract `(kid, alg)` from a token's header without verifying it.
///
/// Useful for selecting a key from a JWKS cache before calling [`validate`].
/// `kid` is `None` when the header omits it; `alg` is the canonical algorithm
/// name (e.g. `"RS256"`). Returns `None` if the token/header is malformed.
pub fn token_header(token: &str) -> Option<(Option<String>, String)> {
    let header = decode_header(token).ok()?;
    Some((header.kid, algorithm_name(header.alg).to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    // A fixed RSA-2048 test key pair (generated for tests only — not a secret).
    const RSA_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDFoPfXsgPFwkE1
8j4p0SgU8mbI2gLkljzjkU4V1am4PSVg9Vn011bV2cSzYZ0mJQYTIYoIKij1eMqB
jGYWa8s2Nh7z5z8WuF1gGXCYj1pvGly+JxSm6qbtmaRIWGHajm3ApFPxZUJAUcYf
9Ha/CKyoWrSv61Qm08NlI9UstIGzDZaeW6b+cintWZo2izG5rDkE1bTtjlkSp+/B
iCvVn3SSgR1rkoj0YYavErFcfzc7fXAT+BRTNFwnUgeN+vCv/3tJnedecwZy1UYk
5O+1epnT9FliEWstKlzKYqCdIiSThsB3wpsHE3vwfs9Bzlk/CiQZM2qNqiQHmtmn
dZY9k9vxAgMBAAECggEACm1c9klNr/xOWCwmVyrScbx9Fiwuio9aD2sQvXqEVb9g
KVajVEBHtB56euPJGK9Lu+xWmJSvjDgUfd5XBT19v31T3RbpOhJ91r6w3/5xopAN
BE69OmCsxbeIC/XMf+1o4V5U5tUquDMNquJJS6NdB2r1wpxo2GhEPyIIstmj8uWf
qosX3h5GbEA3j80MO32nytAbBdu84cIAQHYVze2easasz9hNGMMnPMfQHsYCcfdc
sffIgJHS01r/NrjT2DVGCMhbJih4wEisucyoGucJLq78N0TdgzykTXdBYgO5L7sM
DibbfnE54yCv+EA1D4IRjzp/bphL1wE5N3VgfP2MuQKBgQDzf81A6TDPzMyyOZjg
oZ7AhbvWdL49Anvau888sNm3fi0C6+YyfTJ59qHgQM3LNdmbw8ag9JPlkvdDFxRM
7wAVxUtMbdOefHv4jgLfATu99uTUbiYn+3TEeyAS47IgBrUsU53l9lFJCkH9dxed
qgcBMtghTwbX44gIxHqDvM/d3QKBgQDPxk/urIXB1ezhq0pXeG33aCU+2waFDqNz
PyxSiMyS1ob+9NADtvI+Ec8ueNTheuNpzVaX+nh61enF2ttxcdIuK/U6TH2teXH+
M4l9W61ZeNRsHrep/wu4HKckHlCARyjIaElbJxal7Fot7sfDKsNDk5gB58DkOR6P
CzyF4jrHJQKBgQDJTn49TMw674DHU5DNHTDmz2k0aj2gqL4GXsB812SXK6xAvxAH
67NgW4MGp+y7NKDcAuXiyXDAGllrUNhKpkh2ty6CWEXcv+Op4JYFEbr3WPdjnFDV
OzEVAwnINBBeI82CgPqIVLRs4xsdVmjiwt+ZoRRHrVLmBsi/Hth+swlSzQKBgQCq
d1ETR9aB3sr3p3pZ44ONTZPpSvfBaO4vWrA5kuUMwBeHzEFyGsIKrL/np9k4mYNF
ReP60tPQK/sdil8qZzEDEquixikCj7Y30f7Gq9XAp4LYpicXwRnTVybGWly/siJC
slUlBR/ux8iBEPwyIr6LjedUANlgJYDt6VEhoyeIRQKBgE4uUXknek/CqCzDQRcw
NXecy7WgSLg5aOW8B96hOs3f03CwQg5O1daOYL25GPPcLAI1EzrUwomJQDzWhvtX
viSkdZ5/oxCKUjJ0SycD766B4qORoGKwCyiLBuR1XYoC8uozThPGD3udGtFrTsNA
+XMI8eFSAvLKmBXnW95+Yxen
-----END PRIVATE KEY-----
";

    const RSA_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxaD317IDxcJBNfI+KdEo
FPJmyNoC5JY845FOFdWpuD0lYPVZ9NdW1dnEs2GdJiUGEyGKCCoo9XjKgYxmFmvL
NjYe8+c/FrhdYBlwmI9abxpcvicUpuqm7ZmkSFhh2o5twKRT8WVCQFHGH/R2vwis
qFq0r+tUJtPDZSPVLLSBsw2Wnlum/nIp7VmaNosxuaw5BNW07Y5ZEqfvwYgr1Z90
koEda5KI9GGGrxKxXH83O31wE/gUUzRcJ1IHjfrwr/97SZ3nXnMGctVGJOTvtXqZ
0/RZYhFrLSpcymKgnSIkk4bAd8KbBxN78H7PQc5ZPwokGTNqjaokB5rZp3WWPZPb
8QIDAQAB
-----END PUBLIC KEY-----
";

    // A JWKS carrying the RSA public key above under kid "test-key-1".
    const JWKS_ONE_RSA: &str = r#"{"keys":[{"kty":"RSA","use":"sig","kid":"test-key-1","alg":"RS256","n":"xaD317IDxcJBNfI-KdEoFPJmyNoC5JY845FOFdWpuD0lYPVZ9NdW1dnEs2GdJiUGEyGKCCoo9XjKgYxmFmvLNjYe8-c_FrhdYBlwmI9abxpcvicUpuqm7ZmkSFhh2o5twKRT8WVCQFHGH_R2vwisqFq0r-tUJtPDZSPVLLSBsw2Wnlum_nIp7VmaNosxuaw5BNW07Y5ZEqfvwYgr1Z90koEda5KI9GGGrxKxXH83O31wE_gUUzRcJ1IHjfrwr_97SZ3nXnMGctVGJOTvtXqZ0_RZYhFrLSpcymKgnSIkk4bAd8KbBxN78H7PQc5ZPwokGTNqjaokB5rZp3WWPZPb8Q","e":"AQAB"}]}"#;

    const SECRET: &[u8] = b"super-secret-test-hmac-key-0123456789";
    const ISSUER: &str = "https://issuer.example";
    const AUDIENCE: &str = "my-api";

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs()
    }

    fn base_policy() -> JwtPolicy {
        JwtPolicy {
            algorithms: vec!["HS256".to_string()],
            issuer: Some(ISSUER.to_string()),
            audience: Some(AUDIENCE.to_string()),
            required_scopes: vec!["read".to_string()],
            scope_claim: "scope".to_string(),
        }
    }

    /// Mint an HS256 token from an arbitrary claims value.
    fn mint_hs256(claims: &serde_json::Value) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            claims,
            &EncodingKey::from_secret(SECRET),
        )
        .expect("hs256 encode")
    }

    fn hs_key() -> DecodingKey {
        DecodingKey::from_secret(SECRET)
    }

    #[test]
    fn valid_hs256_token_ok() {
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now() + 3600,
            "scope": "read write",
        });
        let token = mint_hs256(&claims);
        assert_eq!(validate(&token, &hs_key(), &base_policy()), Ok(()));
    }

    #[test]
    fn expired_token_err() {
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now() - 3600,
            "scope": "read",
        });
        let token = mint_hs256(&claims);
        assert_eq!(
            validate(&token, &hs_key(), &base_policy()),
            Err("expired".to_string())
        );
    }

    #[test]
    fn wrong_secret_err() {
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now() + 3600,
            "scope": "read",
        });
        let token = mint_hs256(&claims);
        let wrong = DecodingKey::from_secret(b"a-totally-different-secret-value");
        assert_eq!(
            validate(&token, &wrong, &base_policy()),
            Err("invalid signature".to_string())
        );
    }

    #[test]
    fn wrong_issuer_err() {
        let claims = serde_json::json!({
            "iss": "https://evil.example",
            "aud": AUDIENCE,
            "exp": now() + 3600,
            "scope": "read",
        });
        let token = mint_hs256(&claims);
        assert_eq!(
            validate(&token, &hs_key(), &base_policy()),
            Err("invalid issuer".to_string())
        );
    }

    #[test]
    fn wrong_audience_err() {
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": "some-other-api",
            "exp": now() + 3600,
            "scope": "read",
        });
        let token = mint_hs256(&claims);
        assert_eq!(
            validate(&token, &hs_key(), &base_policy()),
            Err("invalid audience".to_string())
        );
    }

    #[test]
    fn missing_required_scope_err() {
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now() + 3600,
            "scope": "write admin",
        });
        let token = mint_hs256(&claims);
        assert_eq!(
            validate(&token, &hs_key(), &base_policy()),
            Err("missing scope: read".to_string())
        );
    }

    #[test]
    fn scope_present_as_array_ok() {
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now() + 3600,
            "scope": ["read", "write"],
        });
        let token = mint_hs256(&claims);
        assert_eq!(validate(&token, &hs_key(), &base_policy()), Ok(()));
    }

    #[test]
    fn scope_present_as_space_delimited_string_ok() {
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now() + 3600,
            "scope": "read write admin",
        });
        let token = mint_hs256(&claims);
        assert_eq!(validate(&token, &hs_key(), &base_policy()), Ok(()));
    }

    #[test]
    fn alternate_scope_claim_scp_array_ok() {
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now() + 3600,
            "scp": ["read", "write"],
        });
        let token = mint_hs256(&claims);
        let mut policy = base_policy();
        policy.scope_claim = "scp".to_string();
        assert_eq!(validate(&token, &hs_key(), &policy), Ok(()));
    }

    #[test]
    fn token_with_no_exp_err() {
        // No `exp` claim at all → rejected as a missing required claim.
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "scope": "read",
        });
        let token = mint_hs256(&claims);
        assert_eq!(
            validate(&token, &hs_key(), &base_policy()),
            Err("missing required claim: exp".to_string())
        );
    }

    #[test]
    fn token_missing_aud_when_configured_err() {
        // Validly signed, correct issuer, but NO `aud` claim while the policy
        // pins an audience. Must be rejected (not silently accepted).
        let claims = serde_json::json!({
            "iss": ISSUER,
            "exp": now() + 3600,
            "scope": "read",
        });
        let token = mint_hs256(&claims);
        assert_eq!(
            validate(&token, &hs_key(), &base_policy()),
            Err("missing required claim: aud".to_string())
        );
    }

    #[test]
    fn token_missing_iss_when_configured_err() {
        // Validly signed, correct audience, but NO `iss` claim while the policy
        // pins an issuer. Must be rejected.
        let claims = serde_json::json!({
            "aud": AUDIENCE,
            "exp": now() + 3600,
            "scope": "read",
        });
        let token = mint_hs256(&claims);
        assert_eq!(
            validate(&token, &hs_key(), &base_policy()),
            Err("missing required claim: iss".to_string())
        );
    }

    #[test]
    fn no_aud_configured_accepts_token_carrying_aud() {
        // When the policy does NOT pin an audience, a token that happens to
        // carry an `aud` claim must not be spuriously rejected.
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": "whatever-audience",
            "exp": now() + 3600,
            "scope": "read",
        });
        let token = mint_hs256(&claims);
        let mut policy = base_policy();
        policy.audience = None;
        assert_eq!(validate(&token, &hs_key(), &policy), Ok(()));
    }

    #[test]
    fn not_yet_valid_nbf_err() {
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now() + 3600,
            "nbf": now() + 1800,
            "scope": "read",
        });
        let token = mint_hs256(&claims);
        assert_eq!(
            validate(&token, &hs_key(), &base_policy()),
            Err("token not yet valid (nbf)".to_string())
        );
    }

    #[test]
    fn unknown_algorithm_in_policy_err() {
        let claims = serde_json::json!({ "exp": now() + 3600 });
        let token = mint_hs256(&claims);
        let mut policy = base_policy();
        policy.algorithms = vec!["NOPE256".to_string()];
        assert_eq!(
            validate(&token, &hs_key(), &policy),
            Err("unknown algorithm: NOPE256".to_string())
        );
    }

    #[test]
    fn rs256_valid_token_ok() {
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now() + 3600,
            "scope": "read write",
        });
        let enc = EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM.as_bytes()).expect("rsa priv pem");
        let token = encode(&Header::new(Algorithm::RS256), &claims, &enc).expect("rs256 encode");

        let key = DecodingKey::from_rsa_pem(RSA_PUBLIC_PEM.as_bytes()).expect("rsa pub pem");
        let mut policy = base_policy();
        policy.algorithms = vec!["RS256".to_string()];
        assert_eq!(validate(&token, &key, &policy), Ok(()));
    }

    #[test]
    fn rs256_wrong_key_err() {
        // Sign with RSA, but verify against the HMAC secret / an HS256 policy.
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now() + 3600,
            "scope": "read",
        });
        let enc = EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM.as_bytes()).expect("rsa priv pem");
        let token = encode(&Header::new(Algorithm::RS256), &claims, &enc).expect("rs256 encode");

        // Policy only allows RS256 but the key is an HMAC secret → rejected.
        let mut policy = base_policy();
        policy.algorithms = vec!["RS256".to_string()];
        assert!(validate(&token, &hs_key(), &policy).is_err());
    }

    #[test]
    fn rs256_to_hs256_confusion_rejected() {
        // Classic algorithm-confusion attack: the verifier holds an RSA *public*
        // key and expects RS256. The attacker forges an HS256 token using the
        // (public, attacker-known) public-key PEM as the HMAC secret. Because
        // the allow-list is built from the policy (RS256 only) and never from
        // the token header, alg=HS256 is not accepted → rejected.
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now() + 3600,
            "scope": "read",
        });
        let forged = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(RSA_PUBLIC_PEM.as_bytes()),
        )
        .expect("hs256 encode");

        let key = DecodingKey::from_rsa_pem(RSA_PUBLIC_PEM.as_bytes()).expect("rsa pub pem");
        let mut policy = base_policy();
        policy.algorithms = vec!["RS256".to_string()];
        assert!(validate(&forged, &key, &policy).is_err());
    }

    #[test]
    fn hs256_in_policy_with_rsa_key_rejected() {
        // Even a mis-configured policy that lists HS256 alongside an RSA key is
        // rejected up front: jsonwebtoken requires every allow-listed algorithm
        // to share the key's family, so alg-family confusion cannot occur.
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now() + 3600,
            "scope": "read",
        });
        let forged = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(RSA_PUBLIC_PEM.as_bytes()),
        )
        .expect("hs256 encode");

        let key = DecodingKey::from_rsa_pem(RSA_PUBLIC_PEM.as_bytes()).expect("rsa pub pem");
        let mut policy = base_policy();
        policy.algorithms = vec!["RS256".to_string(), "HS256".to_string()];
        assert!(validate(&forged, &key, &policy).is_err());
    }

    #[test]
    fn jwks_one_rsa_key_maps_kid() {
        let keys = decoding_keys_from_jwks(JWKS_ONE_RSA.as_bytes());
        assert_eq!(keys.len(), 1);
        assert!(keys.contains_key("test-key-1"));

        // The selected key actually verifies a token minted with the matching
        // private key.
        let claims = serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": now() + 3600,
            "scope": "read",
        });
        let enc = EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM.as_bytes()).expect("rsa priv pem");
        let token = encode(&Header::new(Algorithm::RS256), &claims, &enc).expect("rs256 encode");
        let key = keys.get("test-key-1").expect("kid present");
        let mut policy = base_policy();
        policy.algorithms = vec!["RS256".to_string()];
        assert_eq!(validate(&token, key, &policy), Ok(()));
    }

    #[test]
    fn jwks_garbage_yields_empty_map() {
        assert!(decoding_keys_from_jwks(b"not json at all").is_empty());
        assert!(decoding_keys_from_jwks(b"").is_empty());
        assert!(decoding_keys_from_jwks(b"{\"keys\": \"nope\"}").is_empty());
        // Well-formed JWKS shell but no usable keys.
        assert!(decoding_keys_from_jwks(b"{\"keys\": []}").is_empty());
    }

    #[test]
    fn token_header_valid_returns_kid_and_alg() {
        let claims = serde_json::json!({ "exp": now() + 3600 });
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".to_string());
        let enc = EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM.as_bytes()).expect("rsa priv pem");
        let token = encode(&header, &claims, &enc).expect("rs256 encode");

        let (kid, alg) = token_header(&token).expect("header parses");
        assert_eq!(kid, Some("test-key-1".to_string()));
        assert_eq!(alg, "RS256");
    }

    #[test]
    fn token_header_without_kid() {
        let claims = serde_json::json!({ "exp": now() + 3600 });
        let token = mint_hs256(&claims);
        let (kid, alg) = token_header(&token).expect("header parses");
        assert_eq!(kid, None);
        assert_eq!(alg, "HS256");
    }

    #[test]
    fn token_header_malformed_returns_none() {
        assert!(token_header("abc").is_none());
        assert!(token_header("").is_none());
        assert!(token_header("only.two").is_none());
    }
}
