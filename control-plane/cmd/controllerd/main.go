package main

import (
	"context"
	"fmt"
	"net"
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
	"github.com/your-org/sentinel-waf/control-plane/internal/certmon"
	chreader "github.com/your-org/sentinel-waf/control-plane/internal/clickhouse"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/diskmon"
	"github.com/your-org/sentinel-waf/control-plane/internal/leader"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/nodehealth"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
	"github.com/your-org/sentinel-waf/control-plane/internal/settings"
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

// allowSuperuserDB reports whether the operator has explicitly opted in to
// running the control plane on a Postgres superuser/BYPASSRLS role. This is only
// safe for single-tenant dev/demo, where RLS is not the tenant boundary.
func allowSuperuserDB() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SENTINEL_ALLOW_SUPERUSER_DB"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
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
			zap.String("error", safeErr(err)))
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

// buildLogger returns the control-plane logger for the requested format.
//
// JSON is the DEFAULT. This used to be zap.NewDevelopmentConfig() with
// CapitalColorLevelEncoder — console encoding with ANSI escape sequences
// embedded in every line. That is unreadable in journald, unparseable by any
// log shipper, and inconsistent with the data plane, which has always emitted
// JSON. A WAF whose control plane cannot be ingested by the customer's own log
// stack is a WAF whose control-plane events are invisible.
//
// SENTINEL_LOG_FORMAT=console (or "dev"/"text") restores the human-readable
// coloured output for local work.
func buildLogger(format string) (*zap.Logger, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "console", "dev", "development", "text":
		cfg := zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		return cfg.Build()
	default:
		cfg := zap.NewProductionConfig()
		// ISO-8601 rather than epoch floats: these lines are read by people in
		// tickets as often as by machines.
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		return cfg.Build()
	}
}

func run() error {
	// ── Logger ────────────────────────────────────────────────────────────────
	log, err := buildLogger(os.Getenv("SENTINEL_LOG_FORMAT"))
	if err != nil {
		return fmt.Errorf("building logger: %w", err)
	}
	defer log.Sync()

	// Install it as the global logger. Without this, zap.L() returns a NO-OP
	// logger and every zap.L() call in the codebase is silently discarded — which
	// included "audit write failed". A failure to append to the tamper-evident
	// audit log was therefore invisible: the write failed, the HTTP request
	// returned 200, and nothing was recorded anywhere. Handlers that hold no
	// logger reference legitimately use zap.L(); it just has to point somewhere.
	zap.ReplaceGlobals(log)

	// ── JWT ───────────────────────────────────────────────────────────────────
	jwtCfg := auth.DefaultJWTConfig()
	jwtCfg.Secret = os.Getenv("SENTINEL_JWT_SECRET")
	devLogin := os.Getenv("SENTINEL_DEV_LOGIN") == "1" || os.Getenv("SENTINEL_DEV_LOGIN") == "true"
	if len(jwtCfg.Secret) < 32 {
		if devLogin {
			log.Warn("SENTINEL_JWT_SECRET missing/weak — dev-login mode: using a random key (tokens reset on restart, HA-unsafe)")
		} else {
			// Fail fast: a random per-process key silently breaks HA (nodes
			// reject each other's tokens) and invalidates all sessions on restart.
			return fmt.Errorf("SENTINEL_JWT_SECRET must be set to a strong value (>=32 chars); set SENTINEL_DEV_LOGIN=1 to bypass for local dev")
		}
	}

	// Audit-log tamper-evidence relies on a real HMAC key — the built-in default
	// makes the hash chain meaningless. Fail fast in prod (bypass for local dev).
	if len(os.Getenv("SENTINEL_AUDIT_HMAC_KEY")) < 32 && !devLogin {
		return fmt.Errorf("SENTINEL_AUDIT_HMAC_KEY must be set to a strong value (>=32 chars); set SENTINEL_DEV_LOGIN=1 to bypass for local dev")
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
			// safeErr, not zap.Error: a connect/parse failure can quote the DSN
			// it choked on, which would put the password in the log.
			log.Warn("DB unavailable — running in degraded mode (mock data only)",
				zap.String("error", safeErr(dbErr)))
		} else {
			log.Info("DB connected", zap.String("url", maskPassword(dbURL)))
			store = db.NewStore(pool)

			// Tenant isolation ultimately rests on FORCE ROW LEVEL SECURITY,
			// which Postgres SILENTLY IGNORES for superusers and BYPASSRLS
			// roles. Refuse to boot as such a role so RLS is never a no-op in
			// multi-tenant use. The explicit tenant_id predicates in the stores
			// are the first line of defense; this assertion is the backstop.
			// SENTINEL_ALLOW_SUPERUSER_DB=1 is an explicit, logged opt-out for
			// single-tenant dev/demo (where RLS is not the isolation boundary).
			privileged, role, perr := store.ConnRoleIsPrivileged(ctx)
			if perr != nil {
				log.Warn("could not verify DB role privileges", zap.Error(perr))
			} else if privileged {
				if allowSuperuserDB() {
					log.Warn("DB role BYPASSES row-level security — tenant isolation relies on explicit predicates only. DO NOT use this role for multi-tenant production.",
						zap.String("db_role", role))
				} else {
					log.Fatal("refusing to start: control plane connects to Postgres as a SUPERUSER/BYPASSRLS role, which nullifies FORCE ROW LEVEL SECURITY (tenant isolation). Point SENTINEL_DB_URL at the non-superuser 'sentinel_app' role, or set SENTINEL_ALLOW_SUPERUSER_DB=1 for single-tenant dev/demo.",
						zap.String("db_role", role))
				}
			}

			// Auto-seed and idempotent schema-ensure require CREATE / cross-
			// tenant INSERT privileges the non-superuser sentinel_app role does
			// not have — in that posture the migrate step (run as the owner
			// role) is responsible for schema + seed. Only run these when
			// connected as a privileged/dev role.
			if privileged {
				if err := db.SeedDev(ctx, pool); err != nil {
					log.Warn("DB seed failed (non-fatal)", zap.Error(err))
				} else {
					log.Info("DB seeded")
				}
				if err := db.EnsureNotificationSchema(ctx, pool); err != nil {
					log.Warn("notification schema ensure failed (non-fatal)", zap.Error(err))
				}
				if err := db.EnsureThreatIntelSchema(ctx, pool); err != nil {
					log.Warn("threat-intel schema ensure failed (non-fatal)", zap.Error(err))
				}
				if err := db.EnsureNodesSchema(ctx, pool); err != nil {
					log.Warn("nodes schema ensure failed (non-fatal)", zap.Error(err))
				}
				if err := db.EnsurePluginSchema(ctx, pool); err != nil {
					log.Warn("plugin schema ensure failed (non-fatal)", zap.Error(err))
				}
				if err := db.EnsureSettingsSchema(ctx, pool); err != nil {
					log.Warn("global_settings schema bootstrap failed (Global Settings page will be read-only)", zap.Error(err))
				}
				if err := db.EnsureLogProfileSchema(ctx, pool); err != nil {
					log.Warn("log profile schema ensure failed (non-fatal)", zap.Error(err))
				}
			} else {
				log.Info("non-superuser DB role — skipping auto-seed/ensure-schema (handled by migrations run as the owner role)")
			}

			// JWT revocation: consult the shared denylist on every Validate so a
			// logout kills the session cluster-wide. Fail OPEN on a DB error (a
			// blip must not lock everyone out). Prune expired rows hourly.
			jwtSvc.SetRevocationChecker(func(jti string) bool {
				revoked, err := store.IsTokenRevoked(context.Background(), jti)
				if err != nil {
					log.Warn("token revocation check failed (fail-open)", zap.Error(err))
					return false
				}
				return revoked
			})

			// Session cut-off: a password reset invalidates every token minted
			// before it. The denylist above cannot express that — it needs a jti,
			// and nothing records the jtis an account currently holds — so this
			// second check answers "was this issued before the credentials
			// changed?" from an in-process map. Unlike revocation it fails CLOSED
			// on a stale cache only in the safe direction: an entry that has not
			// propagated yet simply keeps allowing tokens for up to one refresh
			// interval, while refresh tokens are checked against the database on
			// every use.
			jwtSvc.SetSessionGuard(sessionEpochs.valid)
			startSessionEpochRefresh(context.Background(), store, log)

			// Reclaim spent and expired reset tokens alongside the existing
			// revoked-token prune, so a busy deployment does not accumulate
			// dead single-use rows forever.
			go func() {
				t := time.NewTicker(time.Hour)
				defer t.Stop()
				for {
					<-t.C
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					if n, err := store.CleanupExpiredResetTokens(ctx); err != nil {
						log.Warn("reset-token cleanup failed", zap.Error(err))
					} else if n > 0 {
						log.Info("pruned expired password reset tokens", zap.Int64("rows", n))
					}
					cancel()
				}
			}()
			go func() {
				t := time.NewTicker(time.Hour)
				defer t.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-t.C:
						if _, err := store.CleanupExpiredRevokedTokens(context.Background()); err != nil {
							log.Warn("revoked-token cleanup failed", zap.Error(err))
						}
					}
				}
			}()
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

	// ── RBAC ──────────────────────────────────────────────────────────────────
	enforcer := rbac.NewEnforcer()

	// ── Write-leader election ────────────────────────────────────────────────
	// A single Postgres advisory lock decides which node accepts writes and runs
	// the singleton background workers. Started BEFORE those workers so they can
	// be gated on leadership. Every node participates whenever a database is
	// configured; there is no separate cluster to enable, and no quorum that can
	// be lost independently of Postgres itself.
	cl, clErr := startElector(pool, log)
	if clErr != nil {
		return fmt.Errorf("leader election init failed: %w", clErr)
	}
	if cl != nil {
		// Resign explicitly on shutdown so a successor takes over immediately
		// instead of waiting for Postgres to reap the dropped connection.
		defer cl.Stop()
	}

	// Singleton background duties (alerting, threat-intel, cert & node-health,
	// disk-pressure) MUST run on exactly one node — every control-plane node tails
	// the SAME shared NDJSON stream and shares one Postgres, so running them on all
	// N nodes emits N× duplicate alerts/notifications and N× feed fetches. They run
	// on the current Raft LEADER (R7): a supervisor follows leadership and starts
	// the whole set on acquire, stops it on loss — so losing node 1 while the
	// cluster keeps quorum no longer silently kills the alerting/threat-intel/cert
	// plane. Standalone (no cluster) is always the sole runner.
	if store != nil {
		// Construct + start a fresh set of monitors; returns a stop closure. A
		// fresh set is built on every leadership acquisition (Stop closes each
		// monitor's channel, so instances are single-use).
		startMonitors := func() func() {
			// Node-wide settings: DB override > env > default, re-read by each
			// subsystem on its own tick, so a Global Settings edit is live within
			// a minute and survives a restart. See internal/settings.
			settingsNow := func() settings.Values {
				sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				rows, err := store.ListSettings(sctx, db.DevTenantID, db.DevAdminID)
				if err != nil {
					rows = nil // env/default resolution still applies
				}
				return settings.Snapshot(settingsOverrides(rows))
			}
			eng := alerting.New(store, hub, db.DevTenantID, db.DevAdminID, alertingConfigFromSettings(settingsNow()), log)
			eng.SetConfigSource(func() alerting.Config { return alertingConfigFromSettings(settingsNow()) })
			eng.Start()
			stops := []func(){eng.Stop}
			// Always construct the aggregator: "enabled" is now an operator
			// setting, and a subsystem that only exists when a boot-time env var
			// said so cannot be switched on from the console.
			tiCfg := threatIntelConfigFromSettings(threatintel.ConfigFromEnv(), settingsNow())
			agg := threatintel.New(store, tiCfg, log)
			agg.SetConfigSource(func() threatintel.Config {
				return threatIntelConfigFromSettings(threatintel.ConfigFromEnv(), settingsNow())
			})
			agg.Start(ctx)
			stops = append(stops, agg.Stop)
			if !tiCfg.Enabled {
				log.Info("threat-intel feed fetching disabled in settings (indicators already stored stay enforced)")
			}
			nm := nodehealth.New(store, eng, log)
			nm.Start()
			stops = append(stops, nm.Stop)
			cm := certmon.New(eng, dataPlaneBaseURL(), os.Getenv("SENTINEL_INTERNAL_SECRET"), log)
			cm.Start()
			stops = append(stops, cm.Stop)
			if chClient != nil && chClient.Enabled() {
				dm := diskmon.New(eng, chClient, log)
				dm.Start()
				stops = append(stops, dm.Stop)
			}
			log.Info("singleton monitors started (leader)")
			return func() {
				for i := len(stops) - 1; i >= 0; i-- {
					stops[i]()
				}
				log.Info("singleton monitors stopped (leadership lost)")
			}
		}

		if cl == nil {
			// Standalone = always the sole runner; start once, stop on exit.
			stop := startMonitors()
			defer stop()
		} else {
			// Follow Raft leadership: start the set when this node becomes leader,
			// stop it when leadership moves elsewhere.
			go func() {
				ticker := time.NewTicker(1 * time.Second)
				defer ticker.Stop()
				var stop func()
				for {
					select {
					case <-ctx.Done():
						if stop != nil {
							stop()
						}
						return
					case <-ticker.C:
						leader := cl.IsLeader()
						if leader && stop == nil {
							stop = startMonitors()
						} else if !leader && stop != nil {
							stop()
							stop = nil
						}
					}
				}
			}()
		}
	}

	// The data plane receives configuration by polling GET /api/v1/internal/config
	// over REST (see sync_url in the proxy config). There is deliberately no gRPC
	// listener: the ConfigService that used to run on :9500 had no client on
	// either end — no Rust crate depends on tonic and nothing referenced
	// ConfigService — yet it listened without TLS and registered gRPC server
	// reflection unconditionally, so it served a full schema dump of the
	// management API to anyone who could reach the port. It was removed rather
	// than secured. If config push is ever wanted, add it to the authenticated
	// REST surface instead of reviving a second protocol.
	restAddr := envOrDefault("SENTINEL_REST_ADDR", "0.0.0.0:9501")

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// ── Data plane auto-start ─────────────────────────────────────────────────
	// Try to find and start the Rust proxy binary automatically so the user
	// never has to run a separate command — same behaviour as BunkerWeb/nginx.
	//
	// When the binary is missing the log stream stays EMPTY. It used to fall back
	// to the simulator, which fabricated attacks and streamed them to the
	// dashboard through the same path as real traffic, indistinguishably — a
	// missing binary silently turned the product into a demo. An empty stream is
	// the honest signal that nothing is being observed; the simulator is now an
	// explicit opt-in (SENTINEL_DEV_SIMULATOR=1) for local UI work only.
	proxyRunning := autoStartDataPlane(log)
	switch {
	case proxyRunning:
		log.Info("data-plane started — real traffic logs will appear on the dashboard")
	case hub.StartSimulator():
		log.Warn("SIMULATOR ENABLED — the dashboard is showing FABRICATED data, not real traffic. "+
			"Every entry is tagged source=simulated. Never enable this on a system anyone is relying on.",
			zap.String("disable_by_unsetting", logs.SimulatorEnvVar))
	default:
		log.Warn("data-plane binary not found — no traffic will be observed and the log stream will stay EMPTY. " +
			"Build it with: cargo build -p sentinel-proxy --bin sentinel-bin " +
			"(for UI development only, set SENTINEL_DEV_SIMULATOR=1 to publish clearly-labelled fake data)")
	}

	// ── REST (Gin) ────────────────────────────────────────────────────────────
	router := api.SetupRouter(api.CORSFromEnv())

	// Real readiness (R10): /health stays a cheap static liveness probe, but a
	// node with an unreachable DB or no Raft leader (partitioned / mid-election)
	// must report NotReady so k8s Endpoints + HAProxy stop routing to it. Probes
	// send no JWT, so this is unauthenticated.
	router.GET("/readyz", func(c *gin.Context) {
		ready := true
		checks := gin.H{}
		if store == nil {
			checks["db"] = "unavailable"
			ready = false
		} else {
			ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
			defer cancel()
			if err := store.Ping(ctx); err != nil {
				checks["db"] = "unreachable"
				ready = false
			} else {
				checks["db"] = "ok"
			}
		}
		if cl == nil {
			checks["leader"] = "standalone"
		} else {
			st := cl.Status()
			// A node with no leader in view cannot serve writes, so it must not
			// receive traffic. Note this is NOT a quorum check: leadership depends
			// only on Postgres, so if the database is reachable a leader exists (or
			// is about to, within one campaign interval).
			if st.LeaderID == "" {
				checks["leader"] = "no-leader"
				ready = false
			} else {
				checks["leader"] = st.Role
			}
		}
		code := http.StatusOK
		if !ready {
			code = http.StatusServiceUnavailable
		}
		c.JSON(code, gin.H{"ready": ready, "checks": checks})
	})

	// ── UI is served by the Next.js dashboard, never from here ────────────────
	//
	// The legacy static console (dashboard.html / login.html) used to be served
	// at "/", "/login", "/dashboard" and "/dashboard.html". It was REMOVED, not
	// relocated, because it carried an unauthenticated path to full admin
	// takeover: its live-log view rendered attacker-controlled log fields
	// (User-Agent, request path) into `innerHTML` with no Content-Security-Policy,
	// and it kept the access token in `localStorage`. Any client could plant a
	// payload simply by sending a request through the data plane with a script in
	// its User-Agent; the payload then executed in the next admin session that
	// opened the log view and exfiltrated that admin's token.
	//
	// The Next.js dashboard is a functional superset and escapes log fields
	// before highlighting them (see `escHtml` in app/(dashboard)/logs/page.tsx),
	// so there is nothing to port. In production the data plane's :9443 listener
	// terminates TLS and routes /api/* here and everything else to Next.js.
	//
	// Do not reintroduce server-rendered HTML on the control plane: this process
	// holds the DB credentials and the token-signing key, so any XSS here is an
	// immediate full compromise. UI belongs in the dashboard app.

	authGroup := router.Group("/api/v1/auth")
	{
		authGroup.POST("/login", func(c *gin.Context) { handleLogin(c, jwtSvc, store, hub) })
		authGroup.POST("/refresh", func(c *gin.Context) { handleRefresh(c, jwtSvc, store) })
		// Unauthenticated on purpose: the login page must ask this BEFORE anyone
		// has logged in. It reveals only whether SSO is available — which the
		// login form would reveal anyway by having a button — and never the
		// issuer, client id or secret.
		// Password recovery. Unauthenticated by necessity — the caller is someone
		// who cannot log in. Both endpoints are rate-limited and neither reveals
		// whether an account exists; see password_handlers.go.
		authGroup.POST("/password/forgot", func(c *gin.Context) { handleForgotPassword(c, store, hub, log) })
		authGroup.POST("/password/reset", func(c *gin.Context) { handleResetPassword(c, store, hub, log) })
		authGroup.GET("/oidc/status", handleOIDCStatus)
		authGroup.GET("/oidc/login", func(c *gin.Context) { handleOIDCLogin(c, jwtSvc, log) })
		authGroup.GET("/oidc/callback", func(c *gin.Context) { handleOIDCCallback(c, jwtSvc, store, log) })
	}

	// Machine auth: an X-API-Key header is resolved to Claims via its hash. The
	// lookup is pre-tenant (SECURITY DEFINER carve-out) so it works under the
	// non-superuser DB role with FORCE RLS. Bearer JWTs still take precedence.
	apiKeyResolver := func(ctx context.Context, keyHash string) (*auth.Claims, error) {
		if store == nil {
			return nil, fmt.Errorf("db unavailable")
		}
		a, err := store.LookupAPIKeyByHash(ctx, keyHash)
		if err != nil {
			return nil, err
		}
		return &auth.Claims{
			TenantID:   a.TenantID,
			UserID:     a.CreatedBy,
			Role:       a.Role,
			Scopes:     a.Scopes,
			AuthMethod: "apikey",
		}, nil
	}

	protected := router.Group("/api/v1")
	// Leader-forward BEFORE auth: on a follower we proxy mutating requests to the
	// leader untouched (it authenticates), so any node is a valid write entry point.
	protected.Use(leaderForward(cl))
	protected.Use(auth.GinAuthMiddlewareWithAPIKey(jwtSvc, false, apiKeyResolver))
	{
		protected.POST("/auth/logout", func(c *gin.Context) { handleLogout(c, jwtSvc, store, hub) })
		// Self-service rotation for a signed-in user. Requires the current
		// password, so a borrowed session cannot be turned into ownership.
		protected.POST("/auth/password/change", func(c *gin.Context) { handleChangePassword(c, store, hub, log) })
		protected.POST("/auth/mfa/enroll", func(c *gin.Context) { handleMFAEnroll(c) })
		protected.POST("/auth/mfa/confirm", func(c *gin.Context) { handleMFAConfirm(c, store) })
		protected.POST("/auth/mfa/disable", func(c *gin.Context) { handleMFADisable(c, store) })
		protected.GET("/dashboard/stats", func(c *gin.Context) { handleDashboardStats(c, enforcer, store) })
		protected.GET("/sites", func(c *gin.Context) { handleListSites(c, enforcer, store) })
		protected.GET("/sites/export", func(c *gin.Context) { handleExportSites(c, enforcer, store) })
		protected.POST("/sites/import", func(c *gin.Context) { handleImportSites(c, enforcer, store, hub, cl) })
		protected.POST("/sites", func(c *gin.Context) { handleCreateSite(c, enforcer, store, hub, cl) })
		// Dry run: report whether a proposed site config would be accepted and
		// usable, without writing. Registered before /sites/:id so "validate" is
		// not captured as an :id.
		protected.POST("/sites/validate", func(c *gin.Context) { handleValidateSite(c, enforcer, store) })
		// Config rollback points: list, and restore one.
		protected.GET("/config/versions", func(c *gin.Context) { handleListConfigVersions(c, enforcer, store) })
		protected.POST("/config/versions/:id/rollback", func(c *gin.Context) {
			handleRollbackConfig(c, enforcer, store, hub, cl, log)
		})
		protected.GET("/sites/:id", func(c *gin.Context) { handleGetSite(c, enforcer, store) })
		// Pushed vs held config for one site, with a field diff — the silently-inert detector.
		protected.GET("/sites/:id/effective", func(c *gin.Context) { handleSiteEffectiveConfig(c, enforcer, store) })
		protected.PUT("/sites/:id", func(c *gin.Context) { handleUpdateSite(c, enforcer, store, hub, cl, log) })
		protected.PATCH("/sites/:id", func(c *gin.Context) { handleUpdateSite(c, enforcer, store, hub, cl, log) })
		protected.DELETE("/sites/:id", func(c *gin.Context) { handleDeleteSite(c, enforcer, store, hub, cl, log) })
		protected.PATCH("/sites/:id/status", func(c *gin.Context) { handleUpdateSiteStatus(c, enforcer, store, hub, cl) })
		protected.POST("/sites/:id/exclusions", func(c *gin.Context) { handleAddSiteExclusion(c, enforcer, store, hub, cl) })
		protected.DELETE("/sites/:id/exclusions/:rule_id", func(c *gin.Context) { handleDeleteSiteExclusion(c, enforcer, store, hub, cl) })
		protected.GET("/rules", func(c *gin.Context) { handleListRules(c, enforcer, store) })
		// The compiled set the data plane enforces (per site, with 24h hits) — not the authored store.
		protected.GET("/rules/inventory", func(c *gin.Context) { handleRuleInventory(c, enforcer, chClient) })
		protected.POST("/rules", func(c *gin.Context) { handleCreateRule(c, enforcer, store, hub, cl) })
		// PATCH is a partial update (dsl, severity, phase, tags, enabled, site_id).
		// PUT stays mapped to the enable/disable toggle so existing callers of the
		// old behaviour keep working.
		protected.PATCH("/rules/:id", func(c *gin.Context) { handleUpdateRule(c, enforcer, store, hub, cl) })
		protected.PUT("/rules/:id/enabled", func(c *gin.Context) { handleToggleRule(c, enforcer, store, hub, cl) })
		protected.DELETE("/rules/:id", func(c *gin.Context) { handleDeleteRule(c, enforcer, store, hub, cl) })
		protected.POST("/rules/test", func(c *gin.Context) { handleTestRule(c, enforcer) })
		protected.GET("/ml/stats", func(c *gin.Context) {
			if requirePerm(c, enforcer, rbac.ResourceSite, rbac.ActionList) {
				handleMLStats(c, hub, store)
			}
		})
		protected.GET("/traffic/history", func(c *gin.Context) {
			if requirePerm(c, enforcer, rbac.ResourceSite, rbac.ActionList) {
				handleTrafficHistory(c, hub)
			}
		})
		// WASM plugins. Upload is a .zip containing sentinel-plugin.toml plus the
		// module; a freshly uploaded plugin is inactive until explicitly enabled.
		protected.GET("/plugins", func(c *gin.Context) { handleListPluginsReal(c, enforcer, store) })
		protected.POST("/plugins", func(c *gin.Context) { handleUploadPlugin(c, enforcer, store) })
		protected.PATCH("/plugins/:name", func(c *gin.Context) { handleSetPluginEnabled(c, enforcer, store) })
		protected.DELETE("/plugins/:name", func(c *gin.Context) { handleDeletePlugin(c, enforcer, store) })
		protected.GET("/alerts", func(c *gin.Context) { handleListAlerts(c, enforcer, store) })
		protected.POST("/alerts/:id/ack", func(c *gin.Context) { handleAckAlert(c, enforcer, store, hub, cl) })
		protected.POST("/alerts/:id/resolve", func(c *gin.Context) { handleResolveAlert(c, enforcer, store, hub, cl) })

		// Notification channels (SOC integration: webhook / Slack / syslog / CEF).
		// Node-wide operator settings (alert thresholds, threat-intel feeds) plus
		// the data plane's read-only global config — the Global Settings page.
		// Background jobs: what runs, when it last ran, how it went, run it now.
		protected.GET("/jobs", func(c *gin.Context) { handleListJobs(c, enforcer, cl) })
		protected.POST("/jobs/:name/run", func(c *gin.Context) { handleRunJob(c, enforcer, store, hub, cl) })
		protected.GET("/settings/global", func(c *gin.Context) { handleGetGlobalSettings(c, enforcer, store) })
		protected.PUT("/settings/global", func(c *gin.Context) { handlePutGlobalSettings(c, enforcer, store, hub, cl) })
		protected.DELETE("/settings/global/:key", func(c *gin.Context) { handleDeleteGlobalSetting(c, enforcer, store, hub, cl) })
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
		protected.GET("/events/top-attackers", func(c *gin.Context) { handleTopAttackers(c, enforcer, chClient) })
		protected.GET("/events/severity-timeline", func(c *gin.Context) { handleSeverityTimeline(c, enforcer, chClient) })
		// Support ID → the blocked request (time-range independent).
		protected.GET("/events/support/:id", func(c *gin.Context) { handleSupportIDLookup(c, enforcer, chClient) })
		// Ad-hoc export of the current Threat Search view.
		protected.GET("/events/export", func(c *gin.Context) { handleExportEvents(c, enforcer, store, chClient, hub) })

		// Log profiles — saved per-application log views, and the export that
		// turns one into a file to hand a customer.
		protected.GET("/logs/profiles", func(c *gin.Context) { handleListLogProfiles(c, enforcer, store) })
		protected.POST("/logs/profiles", func(c *gin.Context) { handleCreateLogProfile(c, enforcer, store, hub) })
		protected.PUT("/logs/profiles/:id", func(c *gin.Context) { handleUpdateLogProfile(c, enforcer, store, hub) })
		protected.DELETE("/logs/profiles/:id", func(c *gin.Context) { handleDeleteLogProfile(c, enforcer, store, hub) })
		protected.GET("/logs/profiles/:id/export", func(c *gin.Context) { handleExportLogProfile(c, enforcer, store, chClient, hub) })

		protected.GET("/geoip/blocked", func(c *gin.Context) { handleListBlockedCountries(c, enforcer, store) })
		// Every active block in one place (data-plane bans + block-tier indicators + countries).
		protected.GET("/blocks", func(c *gin.Context) { handleListBlocks(c, enforcer, store) })
		protected.DELETE("/blocks/ip/:ip", func(c *gin.Context) { handleUnblockIP(c, enforcer, store, hub, cl) })
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
				handleLearningReport(c, chClient, hub)
			}
		})
		protected.GET("/audit", func(c *gin.Context) { handleListAudit(c, enforcer, store) })
		// Makes the "tamper-evident" claim exercisable. See handleVerifyAudit.
		protected.GET("/audit/verify", func(c *gin.Context) { handleVerifyAudit(c, enforcer, store) })
		protected.GET("/cluster/status", func(c *gin.Context) {
			if requirePerm(c, enforcer, rbac.ResourceSite, rbac.ActionList) {
				handleClusterStatus(c, cl)
			}
		})
		protected.GET("/cluster/health", func(c *gin.Context) { handleClusterHealth(c, enforcer, store, cl) })
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
	router.GET("/api/v1/internal/config", func(c *gin.Context) { handleInternalConfig(c, store, log) })

	// Internal threat-intel endpoint — the data plane hot-syncs the active IOC
	// set from here (same shared-secret gate as /internal/config).
	router.GET("/api/v1/internal/threat-intel", func(c *gin.Context) { handleInternalThreatIntel(c, store) })

	// Internal node-health heartbeat — data-plane nodes POST their status here
	// (same shared-secret gate as /internal/config).
	router.POST("/api/v1/internal/nodes/heartbeat", func(c *gin.Context) { handleNodeHeartbeat(c, store) })

	// Internal plugin distribution (same shared-secret gate as /internal/config).
	// The listing is a digest — name, version, sha256 — so a node fetches bytes
	// only for modules it does not already hold. This is how an uploaded plugin
	// reaches every WAF node in the fleet: plugins were previously loadable only
	// from a manifest path on a node's own filesystem, which no upload could ever
	// populate and which a 3-node HA fleet could not share.
	router.GET("/api/v1/internal/plugins", func(c *gin.Context) { handleInternalPluginList(c, store) })
	router.GET("/api/v1/internal/plugins/:name/wasm", func(c *gin.Context) { handleInternalPluginWasm(c, store) })

	admin := router.Group("/api/v1/admin")
	admin.Use(leaderForward(cl))
	admin.Use(auth.GinAuthMiddlewareWithAPIKey(jwtSvc, true, apiKeyResolver))
	{
		admin.GET("/users", func(c *gin.Context) { handleListUsersReal(c, enforcer, store) })
		admin.POST("/users", func(c *gin.Context) { handleCreateUserReal(c, enforcer, store, hub) })
		admin.PATCH("/users/:id", func(c *gin.Context) { handleUpdateUser(c, enforcer, store, hub) })
		admin.DELETE("/users/:id", func(c *gin.Context) { handleDeleteUser(c, enforcer, store, hub) })
		// Operator-initiated recovery: mails the user a link. It never sets or
		// returns a password, so an administrator cannot learn a colleague's
		// credentials and act as them afterwards.
		admin.POST("/users/:id/reset-password", func(c *gin.Context) {
			handleAdminResetPassword(c, enforcer, store, hub, log)
		})
		admin.GET("/mail", func(c *gin.Context) { handleMailStatus(c, enforcer) })
		admin.POST("/mail/test", func(c *gin.Context) { handleMailTest(c, enforcer, store, hub, log) })
		admin.GET("/apikeys", func(c *gin.Context) { handleListAPIKeysReal(c, enforcer, store) })
		admin.POST("/apikeys", func(c *gin.Context) { handleCreateAPIKeyReal(c, enforcer, store, hub) })
		admin.DELETE("/apikeys/:id", func(c *gin.Context) { handleRevokeAPIKey(c, enforcer, store, hub) })
	}

	// Platform (tenant lifecycle) — provisioning is gated to the platform tenant's
	// owner/admin (see isPlatformAdmin), distinct from per-tenant admin.
	platform := router.Group("/api/v1/platform")
	platform.Use(leaderForward(cl))
	platform.Use(auth.GinAuthMiddlewareWithAPIKey(jwtSvc, true, apiKeyResolver))
	{
		platform.POST("/tenants", func(c *gin.Context) { handleCreateTenant(c, store) })
		platform.GET("/tenants", func(c *gin.Context) { handleListTenants(c, store) })
		platform.PATCH("/tenants/:id/status", func(c *gin.Context) { handleSetTenantStatus(c, store) })
	}

	// ── Graceful shutdown ─────────────────────────────────────────────────────

	// ReadHeaderTimeout bounds slow-header (slowloris) attacks. We deliberately
	// leave ReadTimeout/WriteTimeout at 0: this server streams Server-Sent Events
	// (live logs) as long-lived GET responses, and a WriteTimeout would sever them.
	httpSrv := &http.Server{Addr: restAddr, Handler: router, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 120 * time.Second}

	go func() {
		log.Info("REST API listening", zap.String("addr", restAddr))
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("REST server failed", zap.Error(err))
			sigCh <- syscall.SIGTERM
		}
	}()

	sig := <-sigCh
	log.Info("shutting down", zap.String("signal", sig.String()))

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
		// Quiet window after which an event-driven alert auto-resolves. 0/unset =
		// 30 min default; a negative value disables auto-resolve entirely.
		AutoResolveAfter: autoResolveFromEnv(),
	}
}

// alertingConfigFromSettings maps the resolved settings snapshot (DB > env >
// default) onto the engine's Config. -1 for auto-resolve means disabled.
func alertingConfigFromSettings(v settings.Values) alerting.Config {
	ar := v.Int("alerting.auto_resolve_secs")
	var auto time.Duration
	switch {
	case ar < 0:
		auto = -1
	case ar > 0:
		auto = time.Duration(ar) * time.Second
	}
	return alerting.Config{
		SpikeWindow:       v.Duration("alerting.window_secs"),
		SpikeThreshold:    int(v.Int("alerting.spike_threshold")),
		OffenderThreshold: int(v.Int("alerting.offender_threshold")),
		Throttle:          v.Duration("alerting.throttle_secs"),
		AutoResolveAfter:  auto,
	}
}

// threatIntelConfigFromSettings overlays the operator-editable keys on the
// env-derived base (HTTP timeout and user agent stay env-only).
func threatIntelConfigFromSettings(base threatintel.Config, v settings.Values) threatintel.Config {
	base.Enabled = v.Bool("threat_intel.enabled")
	base.Interval = v.Duration("threat_intel.interval_secs")
	feed := func(name string) string {
		s := strings.TrimSpace(v.String(name))
		if s == "" {
			return "off"
		}
		return s
	}
	base.TorURL = feed("threat_intel.feed.tor")
	base.FeodoURL = feed("threat_intel.feed.feodo")
	base.URLhausURL = feed("threat_intel.feed.urlhaus")
	base.STIXURL = feed("threat_intel.feed.stix")
	return base
}

// autoResolveFromEnv reads SENTINEL_ALERT_AUTORESOLVE_SECS: unset/0 -> engine
// default, "-1" (or any negative) -> disabled, N>0 -> N seconds.
func autoResolveFromEnv() time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("SENTINEL_ALERT_AUTORESOLVE_SECS")))
	if err != nil || n == 0 {
		return 0
	}
	if n < 0 {
		return -1
	}
	return time.Duration(n) * time.Second
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

// startElector starts Postgres advisory-lock write-leader election.
//
// It replaced startCluster(), which wired up a hand-rolled Raft node from a pile
// of SENTINEL_RAFT_* variables: a numeric node ID, an explicit peer list, a
// listen address, a persistent log directory, a dedicated port, and a shared
// secret that was the sole authenticator on inter-node RPC. All of that is gone.
// Leadership is a single advisory lock in the database every node already talks
// to, so there is no second cluster to configure, secure, or lose quorum in.
//
// Enabled whenever a database is configured. Without one the node is a standalone
// writer, which is the same behaviour as before when Raft was disabled.
//
// Env (all optional):
//
//	SENTINEL_NODE_ID           stable identity for logs/status (default: pod name / hostname)
//	SENTINEL_ADVERTISE_ADDR    host:port peers should forward writes to
//	SENTINEL_POD_NAME          StatefulSet pod name, used to derive the advertise address
//	SENTINEL_HEADLESS_SERVICE  headless Service name, used with SENTINEL_POD_NAME
func startElector(pool db.Pool, log *zap.Logger) (*leader.Elector, error) {
	if pool == nil {
		log.Info("leader election disabled (no database) — running standalone")
		return nil, nil
	}
	lp, ok := pool.(leader.Pool)
	if !ok {
		// Only the pgx pool implements advisory locking; a future sqlite backend
		// would be single-node and needs no election.
		log.Info("leader election unavailable for this database backend — running standalone")
		return nil, nil
	}

	nodeID := leader.NodeID()
	advertise := electorAdvertiseAddr()
	e := leader.New(lp, nodeID, advertise, log.Named("leader"))
	e.Start()
	log.Info("leader election started (Postgres advisory lock)",
		zap.String("node_id", nodeID),
		zap.String("advertise", advertise))
	return e, nil
}

// electorAdvertiseAddr computes the host:port other nodes should forward writes to.
//
// Prefers an explicit override, then the per-pod stable DNS a headless Service
// provides (<pod>.<service>), which resolves within the namespace and survives
// restarts, then the hostname. The port is this node's REST port, because writes
// are forwarded over REST — unlike the Raft setup, which advertised a separate
// consensus port that then had to be rewritten to the REST port on every forward.
func electorAdvertiseAddr() string {
	port := clusterRESTPort()
	if v := strings.TrimSpace(os.Getenv("SENTINEL_ADVERTISE_ADDR")); v != "" {
		if _, _, err := net.SplitHostPort(v); err == nil {
			return v
		}
		return net.JoinHostPort(v, port)
	}
	pod := strings.TrimSpace(os.Getenv("SENTINEL_POD_NAME"))
	svc := strings.TrimSpace(os.Getenv("SENTINEL_HEADLESS_SERVICE"))
	if pod != "" && svc != "" {
		return net.JoinHostPort(pod+"."+svc, port)
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}
