package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// dataPlaneBaseURL is where the Rust WAF proxy serves its internal cert API.
// It is overridable for tests / non-standard deployments (in Docker/K8s the
// control plane and data plane are separate containers, e.g. http://dataplane:8080).
func dataPlaneBaseURL() string {
	return envOrDefault("SENTINEL_DATAPLANE_URL", "http://localhost:9080")
}

// setInternalAuth stamps the shared-secret header so the data plane accepts this
// control-plane→data-plane call across containers — the cert API is otherwise
// loopback-only. No-op when SENTINEL_INTERNAL_SECRET is unset (co-located dev,
// where the call originates from loopback and is allowed anyway).
func setInternalAuth(req *http.Request) {
	if s := os.Getenv("SENTINEL_INTERNAL_SECRET"); s != "" {
		req.Header.Set("X-Sentinel-Internal", s)
	}
}

// certHTTPClient is shared by all cert handlers. ACME issuance can take a while
// (challenge validation), so the timeout is generous.
var certHTTPClient = &http.Client{Timeout: 150 * time.Second}

// ---------------------------------------------------------------------------
// GET /api/v1/certs — list all certificates known to the data plane
// ---------------------------------------------------------------------------

func handleListCerts(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	listReq, _ := http.NewRequest(http.MethodGet, dataPlaneBaseURL()+"/api/v1/internal/certs", nil)
	setInternalAuth(listReq)
	resp, err := certHTTPClient.Do(listReq)
	if err != nil {
		// Data plane down — return empty list so the dashboard renders gracefully.
		c.JSON(http.StatusOK, gin.H{"certs": []any{}, "waf_running": false})
		return
	}
	defer resp.Body.Close()

	var certs []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&certs); err != nil {
		c.JSON(http.StatusOK, gin.H{"certs": []any{}, "waf_running": true})
		return
	}
	c.JSON(http.StatusOK, gin.H{"certs": certs, "waf_running": true})
}

// ---------------------------------------------------------------------------
// POST /api/v1/certs/manual — upload an operator-supplied PEM cert + key
// ---------------------------------------------------------------------------

type manualCertRequest struct {
	Domain  string `json:"domain" binding:"required"`
	Name    string `json:"name"` // optional friendly profile label
	CertPEM string `json:"cert_pem" binding:"required"`
	KeyPEM  string `json:"key_pem" binding:"required"`
}

func handleUploadManualCert(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	var req manualCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Light validation before forwarding — fail fast with a clear message.
	if !strings.Contains(req.CertPEM, "BEGIN CERTIFICATE") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cert_pem does not look like a PEM certificate"})
		return
	}
	if !strings.Contains(req.KeyPEM, "PRIVATE KEY") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "key_pem does not look like a PEM private key"})
		return
	}

	proxyToDataPlane(c, http.MethodPost, "/api/v1/internal/certs/manual", req)
}

// ---------------------------------------------------------------------------
// POST /api/v1/certs/acme — request (or renew) a certificate via ACME
// ---------------------------------------------------------------------------

type acmeCertRequest struct {
	Domains         []string `json:"domains" binding:"required"`
	Email           string   `json:"email" binding:"required"`
	Provider        string   `json:"provider"`          // letsencrypt | letsencrypt_staging | zerossl
	Challenge       string   `json:"challenge"`         // http_01 | tls_alpn_01
	RenewBeforeDays uint32   `json:"renew_before_days"` // default 30
}

func handleRequestAcmeCert(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	var req acmeCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Domains) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one domain is required"})
		return
	}

	proxyToDataPlane(c, http.MethodPost, "/api/v1/internal/certs/acme", req)
}

// ---------------------------------------------------------------------------
// POST /api/v1/certs/:domain/renew — force re-issue using the site's ACME config
// ---------------------------------------------------------------------------

func handleRenewCert(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}
	proxyToDataPlane(c, http.MethodPost, "/api/v1/internal/certs/"+domain+"/renew", nil)
}

// ---------------------------------------------------------------------------
// PATCH /api/v1/certs/:domain — set the friendly profile name for a cert
// ---------------------------------------------------------------------------

type renameCertRequest struct {
	Name string `json:"name"`
}

func handleRenameCert(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}
	var req renameCertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	proxyToDataPlane(c, http.MethodPatch, "/api/v1/internal/certs/"+domain, req)
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/certs/:domain — remove a certificate
// ---------------------------------------------------------------------------

func handleDeleteCert(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceSite, rbac.ActionDelete) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}
	proxyToDataPlane(c, http.MethodDelete, "/api/v1/internal/certs/"+domain, nil)
}

// ---------------------------------------------------------------------------
// Helper: forward a request to the data-plane internal API and relay its reply.
// ---------------------------------------------------------------------------

func proxyToDataPlane(c *gin.Context, method, path string, payload any) {
	var bodyReader io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "marshal failed: " + err.Error()})
			return
		}
		bodyReader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, dataPlaneBaseURL()+path, bodyReader)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	setInternalAuth(req)

	resp, err := certHTTPClient.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "WAF data plane unreachable: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	// Relay the data plane's JSON body and status verbatim.
	c.Data(resp.StatusCode, "application/json", raw)
}
