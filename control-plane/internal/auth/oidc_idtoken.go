package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ID-token verification.
//
// Before this existed, ExchangeToken read the id_token field off the token
// response and threw it away, taking the caller's identity from the UserInfo
// endpoint instead. That skipped the one artifact in the whole flow that is
// cryptographically bound to *this* client and *this* authentication attempt:
//
//   - Nothing checked the signature, so a token response was trusted purely
//     because it arrived over TLS from the configured endpoint.
//   - Nothing checked `aud`, so a token minted for a different relying party at
//     the same IdP would have been accepted.
//   - Nothing checked `exp`, so a stale authentication stayed valid forever.
//   - Nothing checked `nonce`. AuthURL generated one and sent it upstream, but no
//     code path ever compared it to what came back — it was write-only, which
//     left authorization-code replay undetectable.
//   - Nothing compared UserInfo's `sub` to the ID token's `sub`, which OIDC Core
//     5.3.2 requires ("MUST be verified to exactly match ... if they do not
//     match, the UserInfo Response values MUST NOT be used").
//
// Implemented against golang-jwt/jwt/v5, already a dependency, plus a small JWKS
// client — deliberately no new module, since the OIDC libraries pull a large
// dependency tree for what is a bounded amount of verification.

// allowedIDTokenAlgs is an explicit allow-list of asymmetric signing algorithms.
//
// This MUST stay asymmetric-only. Accepting an HMAC family here would let a
// provider's *public* JWKS key be used as an HMAC secret, so anyone who could
// read the (public by definition) JWKS could forge tokens. Leaving the algorithm
// unconstrained is the classic JWT confusion bug; jwt.WithValidMethods below is
// what forecloses it, along with "none".
var allowedIDTokenAlgs = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}

// clockSkew is the tolerance allowed on exp/iat comparisons.
const clockSkew = 2 * time.Minute

// jwksMinRefresh rate-limits key-set refetches so an attacker cannot induce
// unbounded outbound requests by presenting tokens with unknown `kid` values.
const jwksMinRefresh = time.Minute

// IDTokenClaims are the ID-token claims the control plane relies on.
type IDTokenClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Email    string `json:"email"`
	Nonce    string `json:"nonce"`
	Audience []string
	Expiry   time.Time
}

// jwk is a single JSON Web Key (the subset needed for signature verification).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// keyCache caches parsed JWKS public keys per issuer.
type keyCache struct {
	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey // kid -> key ("" holds a single unnamed key)
	fetchedAt time.Time
}

func b64uBigInt(s string) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}

// publicKey converts a JWK into a usable crypto.PublicKey.
func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64uBigInt(k.N)
		if err != nil {
			return nil, fmt.Errorf("jwk: bad RSA modulus: %w", err)
		}
		e, err := b64uBigInt(k.E)
		if err != nil {
			return nil, fmt.Errorf("jwk: bad RSA exponent: %w", err)
		}
		if !e.IsInt64() || e.Int64() < 3 {
			return nil, fmt.Errorf("jwk: implausible RSA exponent")
		}
		// Reject undersized moduli outright rather than letting a weak key
		// verify a token.
		if n.BitLen() < 2048 {
			return nil, fmt.Errorf("jwk: RSA modulus too small (%d bits)", n.BitLen())
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil

	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("jwk: unsupported EC curve %q", k.Crv)
		}
		x, err := b64uBigInt(k.X)
		if err != nil {
			return nil, fmt.Errorf("jwk: bad EC x: %w", err)
		}
		y, err := b64uBigInt(k.Y)
		if err != nil {
			return nil, fmt.Errorf("jwk: bad EC y: %w", err)
		}
		if !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("jwk: EC point is not on curve %s", k.Crv)
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil

	default:
		return nil, fmt.Errorf("jwk: unsupported key type %q", k.Kty)
	}
}

// fetchJWKS retrieves and parses the provider's key set.
func (s *OIDCService) fetchJWKS(ctx context.Context, uri string) (map[string]crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: jwks request: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: jwks fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: jwks endpoint returned %d", resp.StatusCode)
	}

	var set jwks
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("oidc: decoding jwks: %w", err)
	}

	out := make(map[string]crypto.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		// Skip keys explicitly marked for encryption rather than signing.
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			// One malformed or too-weak key must not blind us to the rest.
			continue
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("oidc: jwks contained no usable signing keys")
	}
	return out, nil
}

// signingKeys returns the cached key set, refreshing when a `kid` is unknown.
func (s *OIDCService) signingKeys(ctx context.Context, jwksURI, kid string) (map[string]crypto.PublicKey, error) {
	s.keys.mu.RLock()
	cached, at := s.keys.keys, s.keys.fetchedAt
	s.keys.mu.RUnlock()

	fresh := time.Since(at) < time.Hour
	if cached != nil && fresh {
		if _, ok := cached[kid]; ok || kid == "" {
			return cached, nil
		}
		// Unknown kid: the provider may have rotated. Refetch, but not more
		// often than jwksMinRefresh.
		if time.Since(at) < jwksMinRefresh {
			return cached, nil
		}
	}

	loaded, err := s.fetchJWKS(ctx, jwksURI)
	if err != nil {
		if cached != nil {
			// Serve the cached set rather than failing every login during a
			// transient JWKS outage.
			return cached, nil
		}
		return nil, err
	}

	s.keys.mu.Lock()
	s.keys.keys = loaded
	s.keys.fetchedAt = time.Now()
	s.keys.mu.Unlock()
	return loaded, nil
}

// VerifyIDToken validates an OIDC ID token's signature and claims.
//
// It checks, in order: signature against the provider's JWKS using only
// asymmetric algorithms; `iss` exactly equal to the discovery issuer; `aud`
// containing our client_id; `exp`/`iat` within clockSkew; and `nonce` equal to
// the value minted for this login. Any failure rejects the login.
func (s *OIDCService) VerifyIDToken(ctx context.Context, disco *OIDCDiscovery, rawIDToken, wantNonce string) (*IDTokenClaims, error) {
	if rawIDToken == "" {
		return nil, fmt.Errorf("oidc: provider returned no id_token")
	}
	if disco.JWKSURI == "" {
		return nil, fmt.Errorf("oidc: provider advertises no jwks_uri — cannot verify id_token")
	}

	keyFunc := func(tok *jwt.Token) (interface{}, error) {
		kid, _ := tok.Header["kid"].(string)
		keys, err := s.signingKeys(ctx, disco.JWKSURI, kid)
		if err != nil {
			return nil, err
		}
		if k, ok := keys[kid]; ok {
			return k, nil
		}
		// No `kid` in the header (or no match): only unambiguous when the
		// provider publishes exactly one signing key.
		if len(keys) == 1 {
			for _, k := range keys {
				return k, nil
			}
		}
		return nil, fmt.Errorf("oidc: no JWKS key matches id_token kid %q", kid)
	}

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(rawIDToken, claims, keyFunc,
		jwt.WithValidMethods(allowedIDTokenAlgs),
		jwt.WithLeeway(clockSkew),
		jwt.WithIssuer(disco.Issuer),
		jwt.WithAudience(s.cfg.ClientID),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token verification failed: %w", err)
	}

	// `nonce` binds this token to the authorization request we started, which is
	// what makes authorization-code replay detectable. Constant-time compare.
	gotNonce, _ := claims["nonce"].(string)
	if wantNonce == "" {
		return nil, fmt.Errorf("oidc: no nonce recorded for this login")
	}
	if subtle.ConstantTimeCompare([]byte(gotNonce), []byte(wantNonce)) != 1 {
		return nil, fmt.Errorf("oidc: id_token nonce mismatch (possible replay)")
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("oidc: id_token has no sub")
	}

	out := &IDTokenClaims{Subject: sub, Nonce: gotNonce}
	out.Issuer, _ = claims["iss"].(string)
	out.Email, _ = claims["email"].(string)
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		out.Expiry = exp.Time
	}
	if aud, err := claims.GetAudience(); err == nil {
		out.Audience = aud
	}
	return out, nil
}
