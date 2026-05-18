package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OIDCConfig configures an upstream OpenID Connect provider.
type OIDCConfig struct {
	// ProviderURL is the OIDC issuer URL (e.g. "https://auth.example.com").
	ProviderURL string `yaml:"provider_url" json:"provider_url"`

	// ClientID is the OAuth2 client ID registered with the provider.
	ClientID string `yaml:"client_id" json:"client_id"`

	// ClientSecret is the OAuth2 client secret (never logged).
	ClientSecret string `yaml:"client_secret" json:"-"`

	// RedirectURL is where the provider sends the user after authentication.
	RedirectURL string `yaml:"redirect_url" json:"redirect_url"`

	// Scopes requested from the provider (default: ["openid","profile","email"]).
	Scopes []string `yaml:"scopes" json:"scopes,omitempty"`

	// AllowedDomains restricts OIDC logins to users from these email domains.
	// Empty means any domain is allowed.
	AllowedDomains []string `yaml:"allowed_domains" json:"allowed_domains,omitempty"`
}

// OIDCDiscovery is the OpenID Connect discovery document subset we need.
type OIDCDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// OIDCUserInfo is the normalized user profile returned by the provider.
type OIDCUserInfo struct {
	Subject  string `json:"sub"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Picture  string `json:"picture,omitempty"`
	Provider string `json:"-"` // set by the service
}

// OIDCService handles OpenID Connect provider integration.
type OIDCService struct {
	cfg      OIDCConfig
	client   *http.Client
	mu       sync.RWMutex
	disco    *OIDCDiscovery
	discoAt  time.Time
}

// NewOIDCService creates an OIDC service for the given provider config.
func NewOIDCService(cfg OIDCConfig) *OIDCService {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	return &OIDCService{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Discovery fetches (and caches for 1 hour) the OIDC provider metadata.
func (s *OIDCService) Discovery(ctx context.Context) (*OIDCDiscovery, error) {
	s.mu.RLock()
	if s.disco != nil && time.Since(s.discoAt) < time.Hour {
		d := s.disco
		s.mu.RUnlock()
		return d, nil
	}
	s.mu.RUnlock()

	wellKnown := strings.TrimRight(s.cfg.ProviderURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: discovery returned %d", resp.StatusCode)
	}

	var disco OIDCDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&disco); err != nil {
		return nil, fmt.Errorf("oidc: decoding discovery: %w", err)
	}

	s.mu.Lock()
	s.disco = &disco
	s.discoAt = time.Now()
	s.mu.Unlock()

	return &disco, nil
}

// AuthURL builds the authorization URL the user should be redirected to.
func (s *OIDCService) AuthURL(ctx context.Context, state, nonce string) (string, error) {
	disco, err := s.Discovery(ctx)
	if err != nil {
		return "", err
	}

	u, err := url.Parse(disco.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("oidc: parsing auth endpoint: %w", err)
	}

	q := u.Query()
	q.Set("client_id", s.cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", s.cfg.RedirectURL)
	q.Set("scope", strings.Join(s.cfg.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// ExchangeToken exchanges an authorization code for tokens and user info.
func (s *OIDCService) ExchangeToken(ctx context.Context, code string) (*OIDCUserInfo, error) {
	disco, err := s.Discovery(ctx)
	if err != nil {
		return nil, err
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {s.cfg.RedirectURL},
		"client_id":     {s.cfg.ClientID},
		"client_secret": {s.cfg.ClientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disco.TokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oidc: token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: token exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("oidc: token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("oidc: decoding token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("oidc: no access_token in response")
	}

	// Fetch user info.
	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, disco.UserInfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: userinfo request: %w", err)
	}
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	userResp, err := s.client.Do(userReq)
	if err != nil {
		return nil, fmt.Errorf("oidc: userinfo fetch: %w", err)
	}
	defer userResp.Body.Close()

	if userResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: userinfo returned %d", userResp.StatusCode)
	}

	var info OIDCUserInfo
	if err := json.NewDecoder(io.LimitReader(userResp.Body, 1<<20)).Decode(&info); err != nil {
		return nil, fmt.Errorf("oidc: decoding userinfo: %w", err)
	}
	info.Provider = s.cfg.ProviderURL

	// Domain allow-list check.
	if len(s.cfg.AllowedDomains) > 0 {
		parts := strings.SplitN(info.Email, "@", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("oidc: invalid email from provider")
		}
		allowed := false
		for _, domain := range s.cfg.AllowedDomains {
			if strings.EqualFold(parts[1], domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("oidc: domain %q not allowed", parts[1])
		}
	}

	return &info, nil
}

// NewState returns a random OAuth2 state parameter (CSRF protection).
func NewState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewNonce returns a random OIDC nonce.
func NewNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
