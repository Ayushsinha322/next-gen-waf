package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testClientID = "sentinel-test-client"
	testKID      = "test-key-1"
	testSub      = "user-subject-123"
	testEmail    = "admin@esds.co.in"
)

// testIdP is a minimal OIDC provider: discovery, JWKS, token, and userinfo.
type testIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	// Knobs the tests use to produce a hostile or broken provider.
	userinfoSub   string // defaults to testSub
	userinfoEmail string
	idTokenRaw    string // when set, /token returns this instead of a fresh token
	omitIDToken   bool
	discoIssuer   string // when set, discovery advertises this issuer instead of its own URL
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating test RSA key: %v", err)
	}
	idp := &testIdP{key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss := idp.discoIssuer
		if iss == "" {
			iss = idp.server.URL
		}
		writeJSON(w, map[string]string{
			"issuer":                 iss,
			"authorization_endpoint": idp.server.URL + "/auth",
			"token_endpoint":         idp.server.URL + "/token",
			"userinfo_endpoint":      idp.server.URL + "/userinfo",
			"jwks_uri":               idp.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := key.Public().(*rsa.PublicKey)
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"kid": testKID,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{"access_token": "test-access-token", "token_type": "Bearer"}
		if !idp.omitIDToken {
			resp["id_token"] = idp.idTokenRaw
		}
		writeJSON(w, resp)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		sub := idp.userinfoSub
		if sub == "" {
			sub = testSub
		}
		email := idp.userinfoEmail
		if email == "" {
			email = testEmail
		}
		writeJSON(w, map[string]string{"sub": sub, "email": email, "name": "Test Admin"})
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// mint signs an ID token with the provider's key, allowing every claim to be
// overridden so tests can construct invalid ones.
func (idp *testIdP) mint(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	base := jwt.MapClaims{
		"iss": idp.server.URL,
		"aud": testClientID,
		"sub": testSub,
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	for k, v := range claims {
		if v == nil {
			delete(base, k)
			continue
		}
		base[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, base)
	tok.Header["kid"] = testKID
	signed, err := tok.SignedString(idp.key)
	if err != nil {
		t.Fatalf("signing test id_token: %v", err)
	}
	return signed
}

func (idp *testIdP) service() *OIDCService {
	return NewOIDCService(OIDCConfig{
		ProviderURL:  idp.server.URL,
		ClientID:     testClientID,
		ClientSecret: "test-secret",
		RedirectURL:  "https://waf.example/callback",
	})
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

func TestExchangeTokenAcceptsValidIDToken(t *testing.T) {
	idp := newTestIdP(t)
	const nonce = "nonce-abc"
	idp.idTokenRaw = idp.mint(t, jwt.MapClaims{"nonce": nonce, "email": testEmail})

	info, err := idp.service().ExchangeToken(context.Background(), "code", nonce)
	if err != nil {
		t.Fatalf("valid exchange rejected: %v", err)
	}
	if info.Subject != testSub || info.Email != testEmail {
		t.Errorf("unexpected identity: %+v", info)
	}
}

// ---------------------------------------------------------------------------
// The checks that did not exist before
// ---------------------------------------------------------------------------

func TestExchangeTokenRejectsMissingIDToken(t *testing.T) {
	idp := newTestIdP(t)
	idp.omitIDToken = true
	_, err := idp.service().ExchangeToken(context.Background(), "code", "n")
	assertErrContains(t, err, "no id_token")
}

func TestExchangeTokenRejectsNonceMismatch(t *testing.T) {
	// Authorization-code replay: a token minted for an earlier login carries that
	// login's nonce, which will not match the one this login recorded.
	idp := newTestIdP(t)
	idp.idTokenRaw = idp.mint(t, jwt.MapClaims{"nonce": "nonce-from-an-older-login"})
	_, err := idp.service().ExchangeToken(context.Background(), "code", "nonce-for-this-login")
	assertErrContains(t, err, "nonce mismatch")
}

func TestExchangeTokenRejectsMissingNonceClaim(t *testing.T) {
	idp := newTestIdP(t)
	idp.idTokenRaw = idp.mint(t, nil) // no nonce claim at all
	_, err := idp.service().ExchangeToken(context.Background(), "code", "nonce-for-this-login")
	assertErrContains(t, err, "nonce mismatch")
}

func TestVerifyIDTokenRejectsWrongAudience(t *testing.T) {
	// A token the IdP legitimately minted for a DIFFERENT relying party.
	idp := newTestIdP(t)
	svc := idp.service()
	disco, err := svc.Discovery(context.Background())
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	raw := idp.mint(t, jwt.MapClaims{"aud": "some-other-app", "nonce": "n"})
	_, err = svc.VerifyIDToken(context.Background(), disco, raw, "n")
	assertErrContains(t, err, "verification failed")
}

func TestVerifyIDTokenRejectsWrongIssuer(t *testing.T) {
	idp := newTestIdP(t)
	svc := idp.service()
	disco, err := svc.Discovery(context.Background())
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	raw := idp.mint(t, jwt.MapClaims{"iss": "https://evil.example", "nonce": "n"})
	_, err = svc.VerifyIDToken(context.Background(), disco, raw, "n")
	assertErrContains(t, err, "verification failed")
}

func TestVerifyIDTokenRejectsExpired(t *testing.T) {
	idp := newTestIdP(t)
	svc := idp.service()
	disco, err := svc.Discovery(context.Background())
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	// Well outside clockSkew.
	raw := idp.mint(t, jwt.MapClaims{"exp": time.Now().Add(-1 * time.Hour).Unix(), "nonce": "n"})
	_, err = svc.VerifyIDToken(context.Background(), disco, raw, "n")
	assertErrContains(t, err, "verification failed")
}

func TestVerifyIDTokenRequiresExpiry(t *testing.T) {
	idp := newTestIdP(t)
	svc := idp.service()
	disco, err := svc.Discovery(context.Background())
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	raw := idp.mint(t, jwt.MapClaims{"exp": nil, "nonce": "n"})
	_, err = svc.VerifyIDToken(context.Background(), disco, raw, "n")
	assertErrContains(t, err, "verification failed")
}

func TestVerifyIDTokenRejectsAlgNone(t *testing.T) {
	// The classic unsigned-token bypass.
	idp := newTestIdP(t)
	svc := idp.service()
	disco, err := svc.Discovery(context.Background())
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"iss": idp.server.URL, "aud": testClientID, "sub": testSub, "nonce": "n",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("minting alg=none token: %v", err)
	}
	_, err = svc.VerifyIDToken(context.Background(), disco, raw, "n")
	assertErrContains(t, err, "verification failed")
}

func TestVerifyIDTokenRejectsHMACSignedWithPublicKey(t *testing.T) {
	// Algorithm-confusion: the JWKS modulus is public, so if HS256 were accepted
	// anyone could use it as the HMAC secret and forge tokens at will.
	idp := newTestIdP(t)
	svc := idp.service()
	disco, err := svc.Discovery(context.Background())
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	pub := idp.key.Public().(*rsa.PublicKey)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": idp.server.URL, "aud": testClientID, "sub": testSub, "nonce": "n",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = testKID
	raw, err := tok.SignedString(pub.N.Bytes())
	if err != nil {
		t.Fatalf("minting HS256 token: %v", err)
	}
	_, err = svc.VerifyIDToken(context.Background(), disco, raw, "n")
	assertErrContains(t, err, "verification failed")
}

func TestVerifyIDTokenRejectsSignatureFromAnotherKey(t *testing.T) {
	idp := newTestIdP(t)
	svc := idp.service()
	disco, err := svc.Discovery(context.Background())
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": idp.server.URL, "aud": testClientID, "sub": testSub, "nonce": "n",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = testKID // claims the provider's kid
	raw, err := tok.SignedString(attacker)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	_, err = svc.VerifyIDToken(context.Background(), disco, raw, "n")
	assertErrContains(t, err, "verification failed")
}

func TestExchangeTokenRejectsUserInfoSubMismatch(t *testing.T) {
	// OIDC Core 5.3.2. The ID token verifies, but UserInfo describes a different
	// principal — its values must not be used.
	idp := newTestIdP(t)
	idp.idTokenRaw = idp.mint(t, jwt.MapClaims{"nonce": "n"})
	idp.userinfoSub = "a-completely-different-subject"
	_, err := idp.service().ExchangeToken(context.Background(), "code", "n")
	assertErrContains(t, err, "userinfo sub does not match")
}

func TestDiscoveryRejectsIssuerMismatch(t *testing.T) {
	// A well-known document that points elsewhere must not be accepted, or every
	// downstream `iss` check validates against the attacker's own value.
	idp := newTestIdP(t)
	idp.discoIssuer = "https://evil.example"
	_, err := idp.service().Discovery(context.Background())
	assertErrContains(t, err, "does not match configured provider")
}

func TestExchangeTokenRejectsEmptyRecordedNonce(t *testing.T) {
	// Defence in depth: if the caller lost the nonce, the check would otherwise
	// be vacuous, so an empty recorded nonce must fail closed.
	idp := newTestIdP(t)
	idp.idTokenRaw = idp.mint(t, jwt.MapClaims{"nonce": "whatever"})
	_, err := idp.service().ExchangeToken(context.Background(), "code", "")
	assertErrContains(t, err, "no nonce recorded")
}

// ---------------------------------------------------------------------------
// JWK parsing
// ---------------------------------------------------------------------------

func TestJWKRejectsUndersizedRSAKey(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	pub := small.Public().(*rsa.PublicKey)
	k := jwk{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
	if _, err := k.publicKey(); err == nil {
		t.Fatal("1024-bit RSA key was accepted")
	}
}

func TestJWKRejectsUnsupportedKeyType(t *testing.T) {
	if _, err := (jwk{Kty: "oct"}).publicKey(); err == nil {
		t.Fatal("symmetric key type was accepted")
	}
}

func TestJWKRejectsECPointNotOnCurve(t *testing.T) {
	k := jwk{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes()),
	}
	if _, err := k.publicKey(); err == nil {
		t.Fatal("off-curve EC point was accepted")
	}
}

func TestAllowedAlgsAreAsymmetricOnly(t *testing.T) {
	for _, alg := range allowedIDTokenAlgs {
		if strings.HasPrefix(alg, "HS") || alg == "none" {
			t.Errorf("symmetric or unsigned algorithm %q must not be allow-listed", alg)
		}
	}
}

func assertErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error containing %q, got: %v", want, err)
	}
}
