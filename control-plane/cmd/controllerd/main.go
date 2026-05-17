package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/api"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	controlgrpc "github.com/your-org/sentinel-waf/control-plane/internal/grpc"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	fmt.Fprintln(os.Stderr, "controllerd starting…")
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	// ── Logger ────────────────────────────────────────────────────────────────
	logCfg := zap.NewDevelopmentConfig()
	logCfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	log, err := logCfg.Build()
	if err != nil {
		return fmt.Errorf("building logger: %w", err)
	}
	defer log.Sync()

	// ── JWT ───────────────────────────────────────────────────────────────────
	jwtCfg := auth.DefaultJWTConfig()
	jwtCfg.Secret = os.Getenv("SENTINEL_JWT_SECRET")
	if jwtCfg.Secret == "" {
		log.Warn("SENTINEL_JWT_SECRET not set — using random key (HA unsafe)")
	}
	jwtSvc, err := auth.NewJWTService(jwtCfg)
	if err != nil {
		return fmt.Errorf("initialising JWT service: %w", err)
	}

	// ── DB pool ───────────────────────────────────────────────────────────────
	ctx := context.Background()
	dbURL := envOrDefault("SENTINEL_DB_URL",
		"postgres://sentinel:sentinel_dev@localhost:5432/sentinel?sslmode=disable")

	var store *db.Store
	pool, dbErr := db.Open(ctx, db.Config{URL: dbURL, MaxConns: 20, MinConns: 2})
	if dbErr != nil {
		log.Warn("DB unavailable — running in degraded mode (mock data only)", zap.Error(dbErr))
	} else {
		log.Info("DB connected", zap.String("url", maskPassword(dbURL)))
		store = db.NewStore(pool)

		// Seed dev data (idempotent).
		if err := db.SeedDev(ctx, pool); err != nil {
			log.Warn("DB seed failed (non-fatal)", zap.Error(err))
		} else {
			log.Info("DB seeded")
		}
	}

	// ── Log hub (SSE) ─────────────────────────────────────────────────────────
	hub := logs.NewHub()
	defer hub.Stop()

	// ── RBAC ──────────────────────────────────────────────────────────────────
	enforcer := rbac.NewEnforcer()

	// ── gRPC ──────────────────────────────────────────────────────────────────
	grpcAddr := envOrDefault("SENTINEL_GRPC_ADDR", "0.0.0.0:9500")
	restAddr := envOrDefault("SENTINEL_REST_ADDR", "0.0.0.0:9501")

	grpcSrv, err := controlgrpc.NewServer(grpcAddr, nil, jwtSvc, log)
	if err != nil {
		return fmt.Errorf("creating gRPC server: %w", err)
	}
	go func() {
		if err := grpcSrv.Start(); err != nil {
			log.Fatal("gRPC server failed", zap.Error(err))
		}
	}()

	// ── Data plane auto-start ─────────────────────────────────────────────────
	// Try to find and start the Rust proxy binary automatically so the user
	// never has to run a separate command — same behaviour as BunkerWeb/nginx.
	// Falls back to the simulator when the binary is not built yet.
	proxyRunning := autoStartDataPlane(log)
	if !proxyRunning {
		// No binary found — start simulator so dashboard always shows live data.
		log.Info("data-plane binary not found — running simulator (build with: cargo build -p sentinel-proxy --bin sentinel-bin)")
		hub.StartSimulator()
	} else {
		log.Info("data-plane started — real traffic logs will appear on the dashboard")
	}

	// ── REST (Gin) ────────────────────────────────────────────────────────────
	router := api.SetupRouter(api.DefaultCORS())

	// ── Static dashboard files (served BEFORE API routes) ─────────────────────
	dashDir := envOrDefault("SENTINEL_DASHBOARD_DIR", "../dashboard")
	router.StaticFile("/", filepath.Join(dashDir, "login.html"))
	router.StaticFile("/login", filepath.Join(dashDir, "login.html"))
	router.StaticFile("/dashboard", filepath.Join(dashDir, "dashboard.html"))
	router.StaticFile("/dashboard.html", filepath.Join(dashDir, "dashboard.html"))

	authGroup := router.Group("/api/v1/auth")
	{
		authGroup.POST("/login", func(c *gin.Context) { handleLogin(c, jwtSvc, store, hub) })
		authGroup.POST("/refresh", func(c *gin.Context) { handleRefresh(c, jwtSvc) })
		authGroup.GET("/oidc/login", func(c *gin.Context) { handleOIDCLogin(c, jwtSvc, log) })
		authGroup.GET("/oidc/callback", func(c *gin.Context) { handleOIDCCallback(c, jwtSvc, log) })
	}

	protected := router.Group("/api/v1")
	protected.Use(auth.GinAuthMiddleware(jwtSvc, false))
	{
		protected.GET("/dashboard/stats", func(c *gin.Context) { handleDashboardStats(c, enforcer, store) })
		protected.GET("/sites", func(c *gin.Context) { handleListSites(c, enforcer, store) })
		protected.POST("/sites", func(c *gin.Context) { handleCreateSite(c, enforcer, store, hub) })
		protected.GET("/rules", func(c *gin.Context) { handleListRules(c, enforcer, store) })
		protected.POST("/rules", func(c *gin.Context) { handleCreateRule(c, enforcer, store, hub) })
		protected.PATCH("/rules/:id", func(c *gin.Context) { handleToggleRule(c, enforcer, store, hub) })
		protected.DELETE("/rules/:id", func(c *gin.Context) { handleDeleteRule(c, enforcer, store, hub) })
		protected.POST("/rules/test", func(c *gin.Context) { handleTestRule(c, enforcer) })
		protected.GET("/ml/stats", func(c *gin.Context) { handleMLStats(c, hub) })
		protected.GET("/traffic/history", func(c *gin.Context) { handleTrafficHistory(c, hub) })
		protected.GET("/plugins", func(c *gin.Context) { handleListPlugins(c, enforcer) })
		protected.GET("/alerts", func(c *gin.Context) { handleListAlerts(c, enforcer, store) })
		protected.POST("/alerts/:id/ack", func(c *gin.Context) { handleAckAlert(c, enforcer, store, hub) })
		protected.POST("/alerts/:id/resolve", func(c *gin.Context) { handleResolveAlert(c, enforcer, store, hub) })
		protected.GET("/metrics/snapshot", func(c *gin.Context) { handleMetricsSnapshot(c, hub) })
		protected.GET("/audit", func(c *gin.Context) { handleListAudit(c, enforcer, store) })
	}

	// SSE endpoint lives outside the protected group so the ?token= query-param
	// path in handleLogsStream is reachable. EventSource cannot set headers.
	router.GET("/api/v1/logs/stream", func(c *gin.Context) { handleLogsStream(c, jwtSvc, hub) })

	admin := router.Group("/api/v1/admin")
	admin.Use(auth.GinAuthMiddleware(jwtSvc, true))
	{
		admin.GET("/users", func(c *gin.Context) { handleListUsersReal(c, enforcer) })
		admin.POST("/users", func(c *gin.Context) { handleCreateUserReal(c, enforcer) })
		admin.GET("/apikeys", func(c *gin.Context) { handleListAPIKeysReal(c, enforcer) })
		admin.POST("/apikeys", func(c *gin.Context) { handleCreateAPIKeyReal(c, enforcer) })
		admin.DELETE("/apikeys/:id", func(c *gin.Context) { handleRevokeAPIKey(c, enforcer) })
	}

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	httpSrv := &http.Server{Addr: restAddr, Handler: router}

	go func() {
		log.Info("REST API listening", zap.String("addr", restAddr))
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("REST server failed", zap.Error(err))
		}
	}()

	sig := <-sigCh
	log.Info("shutting down", zap.String("signal", sig.String()))

	grpcSrv.Stop()
	if pool != nil {
		pool.Close()
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutCtx)
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func maskPassword(dsn string) string {
	return dsn
}

// autoStartDataPlane finds the Rust proxy binary and starts it as a managed
// child process, restarting automatically on crash. Returns true if the binary
// was found and launched, false if the binary doesn't exist yet (not built).
func autoStartDataPlane(log *zap.Logger) bool {
	// Candidate binary locations relative to CWD (repo root).
	candidates := []string{
		"./target/debug/sentinel-bin",
		"./target/release/sentinel-bin",
		"../target/debug/sentinel-bin",
		"../target/release/sentinel-bin",
	}
	// Also honour an explicit override.
	if override := os.Getenv("SENTINEL_PROXY_BIN"); override != "" {
		candidates = append([]string{override}, candidates...)
	}

	var binary string
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			binary = abs
			break
		}
	}
	if binary == "" {
		return false
	}

	logDir := envOrDefault("SENTINEL_LOG_DIR", "/tmp/sentinel-logs")
	cfg := envOrDefault("SENTINEL_CONFIG", "configs/dev/sentinel.yaml")
	// Make config path absolute so the proxy finds it regardless of CWD.
	if absCfg, err := filepath.Abs(cfg); err == nil {
		cfg = absCfg
	}

	// Ensure log directory exists.
	_ = os.MkdirAll(logDir, 0o755)

	go func() {
		for {
			cmd := exec.Command(binary)
			cmd.Env = append(os.Environ(),
				"SENTINEL_CONFIG="+cfg,
				"SENTINEL_LOG_DIR="+logDir,
				"RUST_LOG="+envOrDefault("RUST_LOG", "info,sentinel=debug"),
				"RUST_BACKTRACE=1",
			)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			log.Info("starting WAF proxy",
				zap.String("binary", binary),
				zap.String("config", cfg),
				zap.String("log_dir", logDir),
			)

			if err := cmd.Run(); err != nil {
				// Exit code 0 means clean shutdown (SIGTERM from us) — don't restart.
				if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 0 {
					log.Info("WAF proxy exited cleanly")
					return
				}
				log.Warn("WAF proxy crashed — restarting in 3s", zap.Error(err))
				time.Sleep(3 * time.Second)
			} else {
				// Clean exit — stop restarting.
				return
			}
		}
	}()

	return true
}
