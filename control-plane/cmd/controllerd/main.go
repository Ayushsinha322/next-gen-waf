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

	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/your-org/sentinel-waf/control-plane/internal/alerting"
	"github.com/your-org/sentinel-waf/control-plane/internal/api"
	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	chreader "github.com/your-org/sentinel-waf/control-plane/internal/clickhouse"
	"github.com/your-org/sentinel-waf/control-plane/internal/cluster"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	controlgrpc "github.com/your-org/sentinel-waf/control-plane/internal/grpc"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
	"github.com/your-org/sentinel-waf/control-plane/internal/threatintel"
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

// dbConnectMaxWait is how long openDBWithRetry keeps retrying the initial DB
// connection before giving up (then falling back to degraded mode). Override
// with SENTINEL_DB_CONNECT_TIMEOUT (seconds); 0 disables retry. Default 60s.
func dbConnectMaxWait() time.Duration {
	if v := os.Getenv("SENTINEL_DB_CONNECT_TIMEOUT"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 60 * time.Second
}

// openDBWithRetry repeatedly attempts to open the DB pool until it succeeds or
// maxWait elapses, using capped exponential backoff. Each attempt is bounded by
// its own short timeout so a hung connect can't stall startup forever. This
// makes the control plane resilient to start-ordering — Postgres not yet
// accepting connections (docker compose restart, Kubernetes pod ordering) —
// instead of failing into degraded mode on the first ping.
func openDBWithRetry(ctx context.Context, log *zap.Logger, cfg db.Config, maxWait time.Duration) (db.Pool, error) {
	deadline := time.Now().Add(maxWait)
	backoff := time.Second
	const maxBackoff = 5 * time.Second
	for attempt := 1; ; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		pool, err := db.Open(attemptCtx, cfg)
		cancel()
		if err == nil {
			if attempt > 1 {
				log.Info("DB reachable after retry", zap.Int("attempts", attempt))
			}
			return pool, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("db not reachable after %d attempts over %s: %w", attempt, maxWait, err)
		}
		log.Warn("DB not ready yet — retrying",
			zap.Int("attempt", attempt),
			zap.Duration("next_retry_in", backoff),
			zap.Error(err))
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
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
	dbURL := os.Getenv("SENTINEL_DB_URL")
	if dbURL == "" {
		log.Warn("SENTINEL_DB_URL not set — running in degraded mode (mock data only)")
	}

	var store *db.Store
	var pool db.Pool // lifted for shutdown access
	if dbURL != "" {
		var dbErr error
		// Retry with backoff so the control plane survives starting before
		// Postgres is ready (docker compose restart, Kubernetes pod ordering)
		// instead of dropping straight into degraded mode on the first ping.
		pool, dbErr = openDBWithRetry(ctx, log, db.Config{URL: dbURL, MaxConns: 20, MinConns: 2}, dbConnectMaxWait())
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

			// Ensure the notification_channels table exists (idempotent —
			// works even when goose migrations haven't been run manually).
			if err := db.EnsureNotificationSchema(ctx, pool); err != nil {
				log.Warn("notification schema ensure failed (non-fatal)", zap.Error(err))
			}

			// Ensure the threat_intel_iocs table exists (idempotent).
			if err := db.EnsureThreatIntelSchema(ctx, pool); err != nil {
				log.Warn("threat-intel schema ensure failed (non-fatal)", zap.Error(err))
			}
		}
	}

	// ── Log hub (SSE) ─────────────────────────────────────────────────────────
	hub := logs.NewHub()
	defer hub.Stop()

	// ── ClickHouse reader (searchable history; disabled if URL unset) ─────────
	chClient := chreader.FromEnv()
	if chClient.Enabled() {
		log.Info("clickhouse reader enabled (searchable WAF history)")
	} else {
		log.Info("clickhouse reader disabled — set SENTINEL_CLICKHOUSE_URL to enable event search")
	}

	// ── Alert engine ──────────────────────────────────────────────────────────
	// Turns the live WAF event stream into alerts (spikes, repeat offenders,
	// critical blocks), persists them, surfaces them on the dashboard via SSE,
	// and fans them out to configured notification channels. Single-tenant
	// (dev tenant) because the proxy NDJSON stream is not tenant-tagged.
	if store != nil {
		engine := alerting.New(store, hub, db.DevTenantID, db.DevAdminID, alertingConfigFromEnv(), log)
		engine.Start()
		defer engine.Stop()
	}

	// ── Threat Intelligence aggregator ────────────────────────────────────────
	// Ingests open CTI feeds (Tor exit nodes, abuse.ch Feodo/URLhaus, optional
	// STIX/TAXII) into threat_intel_iocs on an hourly ticker; the Rust data plane
	// hot-syncs the result via GET /api/v1/internal/threat-intel. Disable with
	// SENTINEL_THREATINTEL_ENABLED=false (e.g. air-gapped installs).
	if store != nil {
		if tiCfg := threatintel.ConfigFromEnv(); tiCfg.Enabled {
			agg := threatintel.New(store, tiCfg, log)
			agg.Start(ctx)
			defer agg.Stop()
		} else {
			log.Info("threat-intel aggregator disabled (SENTINEL_THREATINTEL_ENABLED=false)")
		}
	}

	// ── RBAC ──────────────────────────────────────────────────────────────────
	enforcer := rbac.NewEnforcer()

	// ── Raft cluster (optional) ──────────────────────────────────────────────
	// Activated when SENTINEL_RAFT_ADDR is set.  Single-node bootstrap when
	// SENTINEL_RAFT_PEERS is empty.  Disabled entirely otherwise — all writes
	// proceed unconditionally, preserving pre-cluster behaviour.
	cl, clErr := startCluster(log)
	if clErr != nil {
		log.Warn("cluster init failed — continuing in standalone mode", zap.Error(clErr))
	} else if cl != nil {
		defer cl.Stop()
	}

	// ── gRPC ──────────────────────────────────────────────────────────────────
	grpcAddr := envOrDefault("SENTINEL_GRPC_ADDR", "0.0.0.0:9500")
	restAddr := envOrDefault("SENTINEL_REST_ADDR", "0.0.0.0:9501")

	grpcSrv, err := controlgrpc.NewServer(grpcAddr, nil, jwtSvc, log)
	if err != nil {
		return fmt.Errorf("creating gRPC server: %w", err)
	}

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := grpcSrv.Start(); err != nil {
			log.Error("gRPC server failed", zap.Error(err))
			sigCh <- syscall.SIGTERM
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
	router := api.SetupRouter(api.CORSFromEnv())

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
		protected.GET("/sites/export", func(c *gin.Context) { handleExportSites(c, enforcer, store) })
		protected.POST("/sites/import", func(c *gin.Context) { handleImportSites(c, enforcer, store, hub, cl) })
		protected.POST("/sites", func(c *gin.Context) { handleCreateSite(c, enforcer, store, hub, cl) })
		protected.GET("/sites/:id", func(c *gin.Context) { handleGetSite(c, enforcer, store) })
		protected.PUT("/sites/:id", func(c *gin.Context) { handleUpdateSite(c, enforcer, store, hub, cl) })
		protected.PATCH("/sites/:id", func(c *gin.Context) { handleUpdateSite(c, enforcer, store, hub, cl) })
		protected.DELETE("/sites/:id", func(c *gin.Context) { handleDeleteSite(c, enforcer, store, hub, cl) })
		protected.PATCH("/sites/:id/status", func(c *gin.Context) { handleUpdateSiteStatus(c, enforcer, store, hub, cl) })
		protected.POST("/sites/:id/exclusions", func(c *gin.Context) { handleAddSiteExclusion(c, enforcer, store, hub, cl) })
		protected.DELETE("/sites/:id/exclusions/:rule_id", func(c *gin.Context) { handleDeleteSiteExclusion(c, enforcer, store, hub, cl) })
		protected.GET("/rules", func(c *gin.Context) { handleListRules(c, enforcer, store) })
		protected.POST("/rules", func(c *gin.Context) { handleCreateRule(c, enforcer, store, hub, cl) })
		protected.PATCH("/rules/:id", func(c *gin.Context) { handleToggleRule(c, enforcer, store, hub, cl) })
		protected.DELETE("/rules/:id", func(c *gin.Context) { handleDeleteRule(c, enforcer, store, hub, cl) })
		protected.POST("/rules/test", func(c *gin.Context) { handleTestRule(c, enforcer) })
		protected.GET("/ml/stats", func(c *gin.Context) {
			if requirePerm(c, enforcer, rbac.ResourceSite, rbac.ActionList) {
				handleMLStats(c, hub)
			}
		})
		protected.GET("/traffic/history", func(c *gin.Context) {
			if requirePerm(c, enforcer, rbac.ResourceSite, rbac.ActionList) {
				handleTrafficHistory(c, hub)
			}
		})
		protected.GET("/plugins", func(c *gin.Context) { handleListPlugins(c, enforcer) })
		protected.GET("/alerts", func(c *gin.Context) { handleListAlerts(c, enforcer, store) })
		protected.POST("/alerts/:id/ack", func(c *gin.Context) { handleAckAlert(c, enforcer, store, hub, cl) })
		protected.POST("/alerts/:id/resolve", func(c *gin.Context) { handleResolveAlert(c, enforcer, store, hub, cl) })

		// Notification channels (SOC integration: webhook / Slack / syslog / CEF).
		protected.GET("/notifications/channels", func(c *gin.Context) { handleListChannels(c, enforcer, store) })
		protected.POST("/notifications/channels", func(c *gin.Context) { handleCreateChannel(c, enforcer, store, hub) })
		protected.PUT("/notifications/channels/:id", func(c *gin.Context) { handleUpdateChannel(c, enforcer, store, hub) })
		protected.DELETE("/notifications/channels/:id", func(c *gin.Context) { handleDeleteChannel(c, enforcer, store, hub) })
		protected.POST("/notifications/channels/:id/test", func(c *gin.Context) { handleTestChannel(c, enforcer, store) })

		// Threat intelligence (dashboard-facing; JWT + RBAC via ResourceThreatIntel).
		// Distinct from the secret-gated data-plane sync at /api/v1/internal/threat-intel.
		protected.GET("/threat-intel/stats", func(c *gin.Context) { handleThreatIntelStats(c, enforcer, store) })
		protected.GET("/threat-intel/iocs", func(c *gin.Context) { handleListIOCs(c, enforcer, store) })
		protected.POST("/threat-intel/iocs", func(c *gin.Context) { handleCreateIOC(c, enforcer, store, hub) })
		protected.DELETE("/threat-intel/iocs/:id", func(c *gin.Context) { handleDeleteIOC(c, enforcer, store, hub) })
		protected.GET("/threat-intel/recent-blocks", func(c *gin.Context) { handleRecentTIBlocks(c, enforcer, chClient) })

		// GeoIP country blocking (global policy applied across active sites).
		// Searchable WAF history (ClickHouse-backed).
		protected.GET("/events/status", func(c *gin.Context) { handleEventsStatus(c, enforcer, chClient) })
		protected.GET("/events/search", func(c *gin.Context) { handleEventsSearch(c, enforcer, chClient) })
		protected.GET("/events/timeline", func(c *gin.Context) { handleEventsTimeline(c, enforcer, chClient) })
		protected.GET("/events/facets", func(c *gin.Context) { handleEventsFacets(c, enforcer, chClient) })

		protected.GET("/geoip/blocked", func(c *gin.Context) { handleListBlockedCountries(c, enforcer, store) })
		protected.POST("/geoip/block", func(c *gin.Context) { handleBlockCountry(c, enforcer, store, hub, cl) })
		protected.DELETE("/geoip/block/:code", func(c *gin.Context) { handleUnblockCountry(c, enforcer, store, hub, cl) })
		protected.GET("/metrics/snapshot", func(c *gin.Context) {
			if requirePerm(c, enforcer, rbac.ResourceSite, rbac.ActionList) {
				handleMetricsSnapshot(c, hub)
			}
		})
		protected.GET("/metrics/sites", func(c *gin.Context) {
			if requirePerm(c, enforcer, rbac.ResourceSite, rbac.ActionList) {
				handleSiteMetrics(c, hub)
			}
		})
		protected.GET("/metrics/learning", func(c *gin.Context) {
			if requirePerm(c, enforcer, rbac.ResourceSite, rbac.ActionList) {
				handleLearningReport(c, hub)
			}
		})
		protected.GET("/audit", func(c *gin.Context) { handleListAudit(c, enforcer, store) })
		protected.GET("/cluster/status", func(c *gin.Context) {
			if requirePerm(c, enforcer, rbac.ResourceSite, rbac.ActionList) {
				handleClusterStatus(c, cl)
			}
		})
		protected.GET("/waf/status", func(c *gin.Context) {
			if requirePerm(c, enforcer, rbac.ResourceSite, rbac.ActionList) {
				handleProxyHealth(c)
			}
		})

		// TLS / ACME certificate management — bridges to the data-plane internal API.
		protected.GET("/certs", func(c *gin.Context) { handleListCerts(c, enforcer) })
		protected.GET("/certs/root-ca", func(c *gin.Context) { handleDownloadRootCA(c, enforcer) })
		protected.GET("/certs/root-ca/info", func(c *gin.Context) { handleRootCAInfo(c, enforcer) })
		// Management-console TLS (the cert the admin UI itself is served with).
		protected.GET("/management-tls", func(c *gin.Context) { handleGetManagementTLS(c, enforcer) })
		protected.POST("/management-tls", func(c *gin.Context) { handleUploadManagementTLS(c, enforcer, store, hub) })
		protected.DELETE("/management-tls", func(c *gin.Context) { handleRevertManagementTLS(c, enforcer, store, hub) })
		protected.POST("/certs/manual", func(c *gin.Context) { handleUploadManualCert(c, enforcer) })
		protected.POST("/certs/acme", func(c *gin.Context) { handleRequestAcmeCert(c, enforcer) })
		protected.POST("/certs/:domain/renew", func(c *gin.Context) { handleRenewCert(c, enforcer) })
		protected.PATCH("/certs/:domain", func(c *gin.Context) { handleRenameCert(c, enforcer) })
		protected.DELETE("/certs/:domain", func(c *gin.Context) { handleDeleteCert(c, enforcer) })
	}

	// SSE endpoint lives outside the protected group so the ?token= query-param
	// path in handleLogsStream is reachable. EventSource cannot set headers.
	router.GET("/api/v1/logs/stream", func(c *gin.Context) { handleLogsStream(c, jwtSvc, enforcer, hub) })

	// Prometheus scrape endpoint (real aggregated WAF metrics). Optionally gated
	// by SENTINEL_METRICS_TOKEN; intended for internal network scraping.
	router.GET("/metrics", func(c *gin.Context) { handleMetrics(c, hub) })

	// Internal config endpoint — called by the Rust data-plane proxy for site
	// hot-sync. No JWT: the proxy runs on the same host (or private network).
	// In production, protect this with mTLS or a network policy.
	router.GET("/api/v1/internal/config", func(c *gin.Context) { handleInternalConfig(c, store) })

	// Internal threat-intel endpoint — the data plane hot-syncs the active IOC
	// set from here (same shared-secret gate as /internal/config).
	router.GET("/api/v1/internal/threat-intel", func(c *gin.Context) { handleInternalThreatIntel(c, store) })

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

	httpSrv := &http.Server{Addr: restAddr, Handler: router}

	go func() {
		log.Info("REST API listening", zap.String("addr", restAddr))
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("REST server failed", zap.Error(err))
			sigCh <- syscall.SIGTERM
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

// alertingConfigFromEnv builds the alert-engine thresholds from optional env
// vars, falling back to defaults inside alerting.New when unset/invalid.
func alertingConfigFromEnv() alerting.Config {
	atoi := func(key string) int { n, _ := strconv.Atoi(os.Getenv(key)); return n }
	secs := func(key string) time.Duration {
		if n, _ := strconv.Atoi(os.Getenv(key)); n > 0 {
			return time.Duration(n) * time.Second
		}
		return 0
	}
	return alerting.Config{
		SpikeWindow:       secs("SENTINEL_ALERT_WINDOW_SECS"),
		SpikeThreshold:    atoi("SENTINEL_ALERT_SPIKE_THRESHOLD"),
		OffenderThreshold: atoi("SENTINEL_ALERT_OFFENDER_THRESHOLD"),
		Throttle:          secs("SENTINEL_ALERT_THROTTLE_SECS"),
	}
}

// autoStartDataPlane finds the Rust proxy binary and starts it as a managed
// child process, restarting automatically on crash. Returns true if the binary
// was found and launched, false if the binary doesn't exist yet (not built).
func autoStartDataPlane(log *zap.Logger) bool {
	// Allow the launcher to own the proxy lifecycle itself. When set to "0"
	// (the dev launcher does this), the control plane does NOT spawn its own
	// proxy, preventing a duplicate data-plane process from running.
	if os.Getenv("SENTINEL_AUTOSTART_DATAPLANE") == "0" {
		log.Info("data-plane auto-start disabled (SENTINEL_AUTOSTART_DATAPLANE=0) — launcher owns the proxy")
		return true
	}
	// Candidate binary locations relative to CWD (repo root).
	// Prefer the optimized release build to keep memory low; fall back to debug.
	candidates := []string{
		"./target/release/sentinel-bin",
		"../target/release/sentinel-bin",
		"./target/debug/sentinel-bin",
		"../target/debug/sentinel-bin",
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

	// Resolve via the shared hub logic (real disk, not tmpfs) and pass it to the
	// spawned proxy so writer and reader always agree on the directory.
	logDir := logs.LogDir()
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

// startCluster reads SENTINEL_RAFT_* env vars and starts a Raft node if
// SENTINEL_RAFT_ADDR is set.  Returns (nil, nil) when Raft is disabled (no
// addr).  Returns (nil, err) on misconfiguration.
//
// Env:
//
//	SENTINEL_NODE_ID      uint64    required if RAFT_ADDR set
//	SENTINEL_RAFT_ADDR    host:port required to enable
//	SENTINEL_RAFT_PEERS   "2=host:9602,3=host:9603"  (empty = single-node)
//	SENTINEL_RAFT_DIR     persistent state dir (default: ./raft-data)
func startCluster(log *zap.Logger) (*cluster.Cluster, error) {
	addr := os.Getenv("SENTINEL_RAFT_ADDR")
	if addr == "" {
		log.Info("Raft disabled (SENTINEL_RAFT_ADDR not set) — running standalone")
		return nil, nil
	}
	idStr := os.Getenv("SENTINEL_NODE_ID")
	peersRaw := os.Getenv("SENTINEL_RAFT_PEERS")

	// Kubernetes StatefulSet mode: a StatefulSet gives every replica identical
	// env, so NODE_ID/PEERS can't be hard-coded per pod. When NODE_ID isn't set
	// explicitly but the pod name is available (downward API →
	// SENTINEL_RAFT_POD_NAME or POD_NAME), derive both from the pod's ordinal:
	// "sentinel-controlplane-2" + replicas=3 + service=<headless> →
	// id=3, peers="1=sentinel-controlplane-0.<svc>:9600,2=...-1.<svc>:9600".
	// This lets the same manifest scale replicas without per-pod config.
	if idStr == "" {
		pod := os.Getenv("SENTINEL_RAFT_POD_NAME")
		if pod == "" {
			pod = os.Getenv("POD_NAME")
		}
		if pod != "" {
			derivedID, derivedPeers, derr := deriveRaftTopology(
				pod,
				os.Getenv("SENTINEL_RAFT_REPLICAS"),
				os.Getenv("SENTINEL_RAFT_SERVICE"),
				envOrDefault("SENTINEL_RAFT_PORT", "9600"),
			)
			if derr != nil {
				return nil, fmt.Errorf("deriving Raft topology from pod ordinal: %w", derr)
			}
			idStr = strconv.FormatUint(derivedID, 10)
			if peersRaw == "" {
				peersRaw = derivedPeers
			}
			log.Info("derived Raft topology from pod ordinal (StatefulSet mode)",
				zap.String("pod", pod),
				zap.String("node_id", idStr),
				zap.String("peers", peersRaw))
		}
	}
	if idStr == "" {
		return nil, fmt.Errorf("SENTINEL_NODE_ID required when SENTINEL_RAFT_ADDR is set " +
			"(or set SENTINEL_RAFT_POD_NAME/_REPLICAS/_SERVICE for StatefulSet mode)")
	}
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil || id == 0 {
		return nil, fmt.Errorf("SENTINEL_NODE_ID must be a positive integer: %v", err)
	}

	peers := map[cluster.NodeID]string{}
	if raw := peersRaw; raw != "" {
		for _, kv := range strings.Split(raw, ",") {
			kv = strings.TrimSpace(kv)
			if kv == "" {
				continue
			}
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid SENTINEL_RAFT_PEERS entry %q (want id=host:port)", kv)
			}
			pid, perr := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 64)
			if perr != nil || pid == 0 {
				return nil, fmt.Errorf("invalid peer id in %q", kv)
			}
			peers[cluster.NodeID(pid)] = strings.TrimSpace(parts[1])
		}
	}

	dataDir := envOrDefault("SENTINEL_RAFT_DIR", filepath.Join(".", "raft-data", idStr))

	// Inter-node RPC must be authenticated with a shared secret. Require it
	// whenever peers are configured (multi-node) so a node on the cluster
	// network can't forge log entries or spoof votes. Single-node clusters
	// exchange no RPC, so the secret is optional there.
	secret := os.Getenv("SENTINEL_RAFT_SECRET")
	if len(peers) > 0 && secret == "" {
		return nil, fmt.Errorf("SENTINEL_RAFT_SECRET is required for a multi-node cluster (peers configured)")
	}

	cfg := cluster.Config{
		NodeID:     cluster.NodeID(id),
		ListenAddr: addr,
		Peers:      peers,
		DataDir:    dataDir,
		Secret:     secret,
		Logger:     log.Named("raft"),
		Apply: func(cmd cluster.Command) error {
			// At apply time the leader has already written through Postgres
			// (DB is shared) and followers re-read state on demand.  This
			// hook is currently a no-op log entry; future work may stream
			// applied commands to the data-plane for live mirroring.
			log.Debug("raft apply",
				zap.String("kind", string(cmd.Kind)),
				zap.Int("payload_bytes", len(cmd.Payload)),
			)
			return nil
		},
	}

	return cluster.Start(cfg)
}

// deriveRaftTopology computes this node's Raft ID and peer list from its
// StatefulSet pod ordinal, so one manifest serves every replica.
//
//	pod="sentinel-controlplane-2", replicas="3", service="sentinel-controlplane-hl", port="9600"
//	  → id=3, peers="1=sentinel-controlplane-0.sentinel-controlplane-hl:9600,
//	                 2=sentinel-controlplane-1.sentinel-controlplane-hl:9600"
//
// Node IDs are 1-based (ordinal+1) because Raft treats 0 as "no node". Peer
// addresses use the per-pod stable DNS a headless Service provides
// (<pod>.<service>), which resolves within the namespace and survives restarts.
func deriveRaftTopology(pod, replicasStr, service, port string) (uint64, string, error) {
	dash := strings.LastIndex(pod, "-")
	if dash < 0 || dash == len(pod)-1 {
		return 0, "", fmt.Errorf("pod name %q has no ordinal suffix (expected name-N)", pod)
	}
	ordinal, err := strconv.Atoi(pod[dash+1:])
	if err != nil || ordinal < 0 {
		return 0, "", fmt.Errorf("pod name %q has a non-ordinal suffix %q", pod, pod[dash+1:])
	}
	prefix := pod[:dash] // e.g. "sentinel-controlplane"

	replicas, err := strconv.Atoi(replicasStr)
	if err != nil || replicas < 1 {
		return 0, "", fmt.Errorf("SENTINEL_RAFT_REPLICAS must be a positive integer, got %q", replicasStr)
	}
	if ordinal >= replicas {
		return 0, "", fmt.Errorf("pod ordinal %d is out of range for %d replicas", ordinal, replicas)
	}
	if service == "" {
		return 0, "", fmt.Errorf("SENTINEL_RAFT_SERVICE (headless service name) is required for StatefulSet mode")
	}

	var peers []string
	for i := 0; i < replicas; i++ {
		if i == ordinal {
			continue // skip self
		}
		peers = append(peers, fmt.Sprintf("%d=%s-%d.%s:%s", i+1, prefix, i, service, port))
	}
	return uint64(ordinal + 1), strings.Join(peers, ","), nil
}
