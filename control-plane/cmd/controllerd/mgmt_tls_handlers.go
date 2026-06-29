package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/certval"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// Management-console TLS certificate management.
//
// Unlike customer-site certs, the management cert secures the admin console
// itself (the dedicated data-plane management listener). Uploads are FULLY
// validated here (key-matches-cert, validity window, SAN, optional chain) before
// being installed — and only the public metadata is ever persisted/audited; the
// private key never touches Postgres, logs, or any response body.

const mgmtTLSInternalPath = "/api/v1/internal/management-tls"

// callDataPlane performs an authenticated request to the data plane's internal
// API and returns the status + raw body (used where we must inspect the result,
// vs. proxyToDataPlane which relays verbatim).
func callDataPlane(method, path string, payload any) (int, []byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, dataPlaneBaseURL()+path, body)
	if err != nil {
		return 0, nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	setInternalAuth(req)
	resp, err := certHTTPClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

// GET /api/v1/management-tls — current management cert metadata (or self-signed default).
func handleGetManagementTLS(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceManagementTLS, rbac.ActionRead) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	proxyToDataPlane(c, http.MethodGet, mgmtTLSInternalPath, nil)
}

// POST /api/v1/management-tls — validate + install a new management certificate.
func handleUploadManagementTLS(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceManagementTLS, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	var req struct {
		CertPEM      string `json:"cert_pem"`
		KeyPEM       string `json:"key_pem"`
		CABundlePEM  string `json:"ca_bundle_pem"`
		Name         string `json:"name"`
		ExpectedHost string `json:"expected_host"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Full validation. On failure, reject WITHOUT logging any PEM material.
	res, err := certval.Validate(req.CertPEM, req.KeyPEM, req.CABundlePEM, req.ExpectedHost)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"valid": false, "error": err.Error()})
		return
	}

	// Best-effort: capture the outgoing cert's fingerprint for the audit trail.
	oldFingerprint := ""
	if st, body, e := callDataPlane(http.MethodGet, mgmtTLSInternalPath, nil); e == nil && st == http.StatusOK {
		var cur struct {
			Fingerprint string `json:"fingerprint"`
		}
		_ = json.Unmarshal(body, &cur)
		oldFingerprint = cur.Fingerprint
	}

	// Install on the data plane (hot-swap). Send the validated metadata so the
	// data plane stores a correct SAN/fingerprint/expiry without re-parsing.
	payload := map[string]any{
		"cert_pem":    req.CertPEM,
		"key_pem":     req.KeyPEM,
		"name":        req.Name,
		"subject":     res.Subject,
		"issuer":      res.Issuer,
		"san":         res.SANs,
		"issued_at":   res.NotBefore,
		"expires_at":  res.NotAfter,
		"fingerprint": res.FingerprintSHA256,
		"key_type":    res.KeyType,
	}
	st, body, e := callDataPlane(http.MethodPost, mgmtTLSInternalPath, payload)
	if e != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "WAF data plane unreachable: " + e.Error()})
		return
	}
	if st != http.StatusOK {
		c.Data(st, "application/json", body)
		return
	}

	// Audit: record old→new fingerprint transition (never the key/PEM).
	diff, _ := json.Marshal(map[string]any{
		"old_fingerprint": oldFingerprint,
		"new_fingerprint": res.FingerprintSHA256,
		"subject":         res.Subject,
		"issuer":          res.Issuer,
		"not_after":       res.NotAfter,
		"key_type":        res.KeyType,
	})
	uid := claims.UserID
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &uid,
		Action:      "management_tls.replace",
		TargetKind:  "management_tls",
		Diff:        diff,
	})

	c.JSON(http.StatusOK, gin.H{"ok": true, "info": res, "warnings": res.Warnings})
}

// DELETE /api/v1/management-tls — revert to the built-in self-signed default.
func handleRevertManagementTLS(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceManagementTLS, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	oldFingerprint := ""
	if st, body, e := callDataPlane(http.MethodGet, mgmtTLSInternalPath, nil); e == nil && st == http.StatusOK {
		var cur struct {
			Fingerprint string `json:"fingerprint"`
		}
		_ = json.Unmarshal(body, &cur)
		oldFingerprint = cur.Fingerprint
	}

	st, body, e := callDataPlane(http.MethodDelete, mgmtTLSInternalPath, nil)
	if e != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "WAF data plane unreachable: " + e.Error()})
		return
	}
	if st != http.StatusOK {
		c.Data(st, "application/json", body)
		return
	}

	diff, _ := json.Marshal(map[string]any{"old_fingerprint": oldFingerprint, "reverted_to": "self_signed"})
	uid := claims.UserID
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &uid,
		Action:      "management_tls.revert",
		TargetKind:  "management_tls",
		Diff:        diff,
	})

	c.JSON(http.StatusOK, gin.H{"ok": true, "reverted": true})
}
