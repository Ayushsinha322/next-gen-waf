package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// An idle stream must still OPEN. The handler wrote the 200 but flushed nothing
// until the first log entry, so the browser's EventSource never fired onopen:
// after a control-plane restart — empty backlog, quiet site — the Logs page sat
// on "Reconnecting" indefinitely while the stream was in fact healthy. Seen on
// .71 on 2026-09-25; one request to the site flipped it to Live.
func TestLogsStreamOpensBeforeAnyEntry(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("SENTINEL_LOG_DIR", t.TempDir())

	jwtSvc, err := auth.NewJWTService(auth.JWTConfig{Secret: strings.Repeat("k", 48)})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwtSvc.IssueAccessToken(auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "u1"},
		TenantID:         "t1", UserID: "u1", Role: "admin", AuthMethod: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	hub := logs.NewHub()
	defer hub.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/logs/stream?token="+tok, nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = req

	handleLogsStream(c, jwtSvc, rbac.NewEnforcer(), hub) // returns when ctx expires

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !rec.Flushed {
		t.Fatal("nothing was flushed on an idle stream — the browser never sees it open")
	}
	if !strings.HasPrefix(rec.Body.String(), ":") {
		t.Fatalf("idle stream should start with an SSE comment, got %q", rec.Body.String())
	}
}
