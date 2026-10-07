package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/your-org/sentinel-waf/control-plane/internal/db"
)

// runSubcommand runs a one-shot command given as the first argument and
// reports whether there was one; with none the server starts as always.
//
//	healthcheck   the container healthcheck (the image has no shell or HTTP client)
//	reset-admin   the break-glass way back in for a lost administrator
func runSubcommand(args []string) (code int, handled bool) {
	if len(args) == 0 {
		return 0, false
	}
	switch args[0] {
	case "healthcheck":
		return healthcheck(os.Stderr), true
	case "reset-admin":
		return resetAdminCmd(args[1:], os.Stdout, os.Stderr), true
	}
	return 0, false
}

// healthcheck asks this container's own server whether it is ready: /readyz
// answers 200 only with the database reachable. There was no healthcheck, so
// a control plane that had lost its database read "running" to Docker and to
// the rolling update.
func healthcheck(stderr io.Writer) int {
	port := "9501"
	if _, p, err := net.SplitHostPort(envOrDefault("SENTINEL_REST_ADDR", "0.0.0.0:9501")); err == nil && p != "" {
		port = p
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/readyz")
	if err != nil {
		fmt.Fprintln(stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		fmt.Fprintf(stderr, "healthcheck: /readyz answered %s %s\n", resp.Status, strings.TrimSpace(string(body)))
		return 1
	}
	return 0
}

// resetAdminCmd gives an administrator account a new password, run inside the
// control-plane container:
//
//	docker exec -it sentinel-controlplane-1 controllerd reset-admin [--email you@example.com]
//
// Only someone with root on the host can do that, which is the point: it is
// the way back in when the password is lost and no mail relay is configured,
// a case the installer used to describe as "there is no way back in".
func resetAdminCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("reset-admin", flag.ContinueOnError)
	fs.SetOutput(stderr)
	email := fs.String("email", "", "the administrator's login (default: the bootstrap administrator's)")
	tenant := fs.String("tenant", db.DevTenantID, "the tenant id (the default tenant unless you run several)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	login := strings.TrimSpace(*email)
	if login == "" {
		login = db.BootstrapAdminEmail()
	}
	dbURL := os.Getenv("SENTINEL_DB_URL")
	if dbURL == "" {
		fmt.Fprintln(stderr, "reset-admin: SENTINEL_DB_URL is not set — run this inside the control-plane container:")
		fmt.Fprintln(stderr, "  docker exec -it sentinel-controlplane-1 controllerd reset-admin")
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, db.Config{URL: dbURL, MaxConns: 2, MinConns: 1})
	if err != nil {
		fmt.Fprintln(stderr, "reset-admin: database:", safeErr(err))
		return 1
	}
	defer pool.Close()
	store := db.NewStore(pool)

	password, created, userID, err := store.ResetAdmin(ctx, *tenant, login)
	if err != nil {
		fmt.Fprintln(stderr, "reset-admin:", err)
		return 1
	}
	target := userID
	if err := store.WriteAuditLog(ctx, db.WriteAuditRequest{
		TenantID:   *tenant,
		Action:     "user.reset_admin",
		TargetKind: "user",
		TargetID:   &target,
	}, []byte(os.Getenv("SENTINEL_AUDIT_HMAC_KEY"))); err != nil {
		fmt.Fprintln(stderr, "reset-admin: WARNING: the reset is done, but writing it to the audit log failed:", err)
	}

	verb := "reset"
	if created {
		verb = "created"
	}
	fmt.Fprintf(stdout, "Administrator %s: %s\n", verb, login)
	fmt.Fprintf(stdout, "Password (shown once): %s\n", password)
	fmt.Fprintln(stdout, "Sign in, then change it: account menu → Change password.")
	fmt.Fprintln(stdout, "Earlier sessions and reset links of this account no longer work; its MFA is cleared.")
	return 0
}
