package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/your-org/sentinel-waf/control-plane/internal/auth"
	"github.com/your-org/sentinel-waf/control-plane/internal/db"
	"github.com/your-org/sentinel-waf/control-plane/internal/logs"
	"github.com/your-org/sentinel-waf/control-plane/internal/mailer"
	"github.com/your-org/sentinel-waf/control-plane/internal/rbac"
)

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------
//
// The forgot-password endpoint is unauthenticated and always answers "if that
// account exists, we sent a link" — which means a caller gets no feedback and
// can therefore hammer it freely unless something counts. These reuse the
// existing loginGuard, whose "failure" counter is really an attempt counter; we
// record EVERY request, not just failures, because on this endpoint there is no
// such thing as an observable failure.
//
// Per-account is the tighter limit: it caps how much mail one inbox can be made
// to receive (a reset-mail bomb is the realistic abuse here). Per-IP is looser
// so an office behind one NAT address is not locked out by a few colleagues.
var (
	resetRequestByAccount = newLoginGuard(3, 15*time.Minute, 15*time.Minute)
	resetRequestByIP      = newLoginGuard(15, 15*time.Minute, 15*time.Minute)
	// Redemption is guarded separately. A 256-bit token is not guessable, so
	// this exists to stop the endpoint being used as a free argon2 oracle rather
	// than to protect the token itself.
	resetRedeemByIP = newLoginGuard(20, 15*time.Minute, 15*time.Minute)
)

// ---------------------------------------------------------------------------
// Session cut-off cache
// ---------------------------------------------------------------------------

// sessionEpochs answers "is a token minted at time T for user U still valid?"
// without a database round trip on every authenticated request.
//
// It is authoritative on the node that EXECUTED the write and eventually
// consistent elsewhere, refreshed from the database on a timer by main().
//
// In a cluster that distinction is sharper than it first looks. Mutating
// requests are leader-forwarded, so when a user changes their password against
// a follower the write — and the inline cache update — happen on the LEADER.
// The follower the user is actually talking to learns about it only on its next
// refresh. Measured on the 3-node deployment: the leader rejected the old access
// token immediately while both followers served it until the tick.
//
// Hence sessionEpochRefreshInterval below is short. Refresh tokens never depend
// on this at all — handleRefresh re-reads the row, so the long-lived credential
// is checked against the database itself on every use, on every node.
type sessionEpochCache struct {
	mu sync.RWMutex
	m  map[string]time.Time
}

func newSessionEpochCache() *sessionEpochCache {
	return &sessionEpochCache{m: make(map[string]time.Time)}
}

// valid reports whether a token issued at issuedAt is still acceptable.
//
// JWT "iat" has whole-second precision, so the stored cut-off is compared at
// second granularity too. Rounding the cut-off DOWN means a token minted in the
// same second as the reset is accepted — a sub-second window, taken knowingly,
// because rounding the other way would reject the fresh token from the login
// that immediately follows a reset and lock the user out of their own recovery.
func (s *sessionEpochCache) valid(userID string, issuedAt time.Time) bool {
	s.mu.RLock()
	epoch, ok := s.m[userID]
	s.mu.RUnlock()
	if !ok {
		return true
	}
	return !issuedAt.Before(epoch.Truncate(time.Second))
}

func (s *sessionEpochCache) set(userID string, t time.Time) {
	s.mu.Lock()
	s.m[userID] = t
	s.mu.Unlock()
}

// replace swaps in a freshly loaded snapshot, preserving any entry that is newer
// than what the database returned. Without that, a reset performed on this node
// microseconds before a refresh completes would be rolled back by stale data and
// the just-signed-out sessions would come back to life.
func (s *sessionEpochCache) replace(fresh map[string]time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, local := range s.m {
		if remote, ok := fresh[id]; !ok || local.After(remote) {
			fresh[id] = local
		}
	}
	s.m = fresh
}

var sessionEpochs = newSessionEpochCache()

// sessionEpochRefreshInterval bounds how long a follower can keep honouring an
// access token that a password change on the leader already invalidated.
//
// The query behind it is `WHERE sessions_valid_from IS NOT NULL`, so it returns
// only accounts that have ever been reset — a handful of rows on a real
// deployment, not the user table. That is cheap enough to run often, and running
// it often is the whole point: at the previous 30s this window was the largest
// remaining gap in "a password change signs you out everywhere".
const sessionEpochRefreshInterval = 5 * time.Second

// startSessionEpochRefresh keeps the cache in step with other cluster nodes.
func startSessionEpochRefresh(ctx context.Context, store *db.Store, log *zap.Logger) {
	if store == nil {
		return
	}
	load := func() {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		fresh, err := store.SessionEpochs(c)
		if err != nil {
			log.Warn("session epoch refresh failed; using cached cut-offs", zap.Error(err))
			return
		}
		sessionEpochs.replace(fresh)
	}
	load()
	go func() {
		t := time.NewTicker(sessionEpochRefreshInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				load()
			}
		}
	}()
}

// ---------------------------------------------------------------------------
// Password policy
// ---------------------------------------------------------------------------

// minPasswordLen matches the 12-character floor already enforced when an
// administrator creates a user, so a reset cannot be used to install a weaker
// password than the account could have been created with.
const minPasswordLen = 12

// validatePassword returns a message describing why a password is unacceptable,
// or "" when it is fine.
//
// Length carries most of the weight; the class requirement is deliberately mild
// (two of four) so it nudges without pushing people toward "Password1!".
func validatePassword(pw string) string {
	if len(pw) < minPasswordLen {
		return fmt.Sprintf("password must be at least %d characters", minPasswordLen)
	}
	if len(pw) > 256 {
		return "password must be 256 characters or fewer"
	}
	var lower, upper, digit, other bool
	for _, r := range pw {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, ok := range []bool{lower, upper, digit, other} {
		if ok {
			classes++
		}
	}
	if classes < 2 {
		return "password must combine at least two of: lower case, upper case, digits, symbols"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Mail plumbing
// ---------------------------------------------------------------------------

// currentMailer builds a Mailer from the environment on each use so that an
// operator changing SMTP settings does not have to restart the control plane.
func currentMailer() *mailer.Mailer { return mailer.New(mailer.FromEnv()) }

// resetLink builds the URL mailed to the user.
//
// The base MUST come from configuration. Deriving it from the request's Host
// header would let an unauthenticated caller point the link at a host they
// control — the request body already carries the victim's address, so the
// attacker would receive a working reset link for someone else's account. That
// is host-header injection, and refusing to guess is the fix.
func resetLink(base, token string) (string, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return "", errors.New("SENTINEL_PUBLIC_URL is not set, so no reset link can be built")
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("SENTINEL_PUBLIC_URL is not a valid absolute URL: %q", base)
	}
	return fmt.Sprintf("%s/reset-password?token=%s", base, url.QueryEscape(token)), nil
}

// sendResetMail delivers the reset link and, on success, the operator notice.
// Runs detached from the request so a slow relay cannot hold the response open
// (and so response time stays constant whether or not the account existed).
func sendResetMail(m *mailer.Mailer, acct db.ResetAccount, link string, expiresAt time.Time,
	byAdmin bool, sourceIP string, log *zap.Logger) error {

	msg := mailer.ResetEmail(acct.Name, link, expiresAt, byAdmin)
	msg.To = acct.Email
	if err := m.Send(msg); err != nil {
		// The link is NEVER logged, here or anywhere. Only the failure is.
		log.Error("password reset mail could not be sent",
			zap.String("event", "password.reset.mail_failed"), zap.Error(err))
		return err
	}
	log.Info("password reset mail sent", zap.String("event", "password.reset.mail_sent"))
	return nil
}

// notifySecurityContact mails the deployment's security address. Best-effort:
// the reset itself has already succeeded and must not be undone because a
// notification bounced.
func notifySecurityContact(m *mailer.Mailer, userEmail, sourceIP, initiatedBy string, log *zap.Logger) {
	cfg := m.Config()
	if cfg.NotifyEmail == "" || !cfg.Configured() {
		return
	}
	msg := mailer.AdminNoticeEmail(userEmail, sourceIP, initiatedBy, time.Now())
	msg.To = cfg.NotifyEmail
	if err := m.Send(msg); err != nil {
		log.Warn("security-contact notification failed", zap.Error(err))
	}
}

// ---------------------------------------------------------------------------
// POST /api/v1/auth/password/forgot
// ---------------------------------------------------------------------------

// handleForgotPassword starts a self-service reset.
//
// The response is identical for a known address, an unknown address, a locked-out
// caller and a mail failure. That is the entire point: this endpoint is the
// classic account-enumeration oracle, and anything that varies — status code,
// body, or timing — hands an attacker a list of valid accounts. All the real
// work therefore happens after the response is decided.
func handleForgotPassword(c *gin.Context, store *db.Store, hub *logs.Hub, log *zap.Logger) {
	var req struct {
		Email string `json:"email"`
	}
	_ = c.ShouldBindJSON(&req)
	email := strings.ToLower(strings.TrimSpace(req.Email))

	// One response, always. Declared up front so no branch below can forget it.
	const genericMsg = "If that email address has an account, a password reset link has been sent to it."
	respond := func() {
		c.JSON(http.StatusOK, gin.H{"ok": true, "message": genericMsg})
	}

	if email == "" || len(email) > 320 {
		respond()
		return
	}

	ipKey := "ip:" + c.ClientIP()
	accountLocked, _ := resetRequestByAccount.locked(email)
	ipLocked, _ := resetRequestByIP.locked(ipKey)
	// Count the attempt whether or not it is going to be served, so a caller
	// cannot stay under the limit by spraying addresses that do not exist.
	resetRequestByAccount.recordFailure(email)
	resetRequestByIP.recordFailure(ipKey)
	if accountLocked || ipLocked {
		log.Warn("password reset request rate-limited",
			zap.String("event", "password.reset.rate_limited"),
			zap.String("ip", c.ClientIP()))
		respond()
		return
	}

	if store == nil {
		log.Error("password reset requested but no user database is configured")
		respond()
		return
	}

	acct, found, err := store.LookupResetAccount(c.Request.Context(), email)
	if err != nil {
		log.Error("password reset lookup failed", zap.Error(err))
		respond()
		return
	}

	// Audit the REQUEST even when the address matches nothing, so a spray shows
	// up in the trail. Target is nil for an unknown address — there is no user to
	// point at, and inventing one would put an unverified address in the log.
	auditReq := &db.WriteAuditRequest{
		TenantID:   db.DevTenantID,
		Action:     "user.password.reset_requested",
		TargetKind: "user",
	}
	if found {
		acctID := acct.UserID
		auditReq.TenantID = acct.TenantID
		auditReq.TargetID = &acctID
	}
	writeAuditEntry(c, store, hub, auditReq)

	if !found {
		respond()
		return
	}

	m := currentMailer()
	if !m.Config().Configured() {
		// Deliberately still the generic response. An operator discovers this
		// from the log and the settings page, not by having the API tell an
		// anonymous caller how this deployment is configured.
		log.Error("password reset requested but SMTP is not configured; no mail sent",
			zap.String("event", "password.reset.smtp_unconfigured"))
		respond()
		return
	}

	token, expiresAt, err := store.CreateResetToken(c.Request.Context(), acct,
		db.DefaultResetTTL, c.ClientIP(), "self")
	if err != nil {
		log.Error("could not mint password reset token", zap.Error(err))
		respond()
		return
	}
	link, err := resetLink(m.Config().PublicURL, token)
	if err != nil {
		log.Error("password reset link could not be built", zap.Error(err))
		respond()
		return
	}

	sourceIP := c.ClientIP()
	go func() {
		_ = sendResetMail(m, acct, link, expiresAt, false, sourceIP, log)
	}()
	respond()
}

// ---------------------------------------------------------------------------
// POST /api/v1/auth/password/reset
// ---------------------------------------------------------------------------

// handleResetPassword redeems a token and installs the new password.
func handleResetPassword(c *gin.Context, store *db.Store, hub *logs.Hub, log *zap.Logger) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token and password are required"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	ipKey := "reset:" + c.ClientIP()
	if locked, wait := resetRedeemByIP.locked(ipKey); locked {
		c.Header("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())+1))
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many attempts; try again later"})
		return
	}

	// Validate the password BEFORE burning the token. Rejecting a weak password
	// after consuming a single-use link would leave the user holding a dead link
	// and no way back in.
	if problem := validatePassword(req.Password); problem != "" {
		resetRedeemByIP.recordFailure(ipKey)
		c.JSON(http.StatusBadRequest, gin.H{"error": problem})
		return
	}

	acct, initiatedBy, err := store.ConsumeResetToken(c.Request.Context(), req.Token)
	if err != nil {
		resetRedeemByIP.recordFailure(ipKey)
		if errors.Is(err, db.ErrResetTokenInvalid) {
			// One message for unknown, expired and already-used, so redemption
			// cannot be used to probe which tokens ever existed.
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "this reset link is invalid or has expired — request a new one",
			})
			return
		}
		log.Error("reset token redemption failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not process reset"})
		return
	}

	if err := store.SetPassword(c.Request.Context(), acct.TenantID, acct.UserID,
		acct.UserID, req.Password); err != nil {
		log.Error("could not set new password after valid reset", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not set the new password"})
		return
	}

	// Cut every session for this account on this node immediately; other nodes
	// pick it up on their next refresh, and refresh tokens are checked against
	// the database regardless.
	sessionEpochs.set(acct.UserID, time.Now().UTC())
	resetRequestByAccount.recordSuccess(strings.ToLower(acct.Email))
	loginAttempts.recordSuccess(strings.ToLower(acct.Email))

	userID := acct.UserID
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    acct.TenantID,
		ActorUserID: &userID,
		Action:      "user.password.reset",
		TargetKind:  "user",
		TargetID:    &userID,
	})
	log.Info("console password reset completed",
		zap.String("event", "password.reset.completed"),
		zap.String("user_id", userID),
		zap.String("initiated_by", initiatedBy))

	m := currentMailer()
	sourceIP := c.ClientIP()
	userEmail := acct.Email
	userName := acct.Name
	go func() {
		if m.Config().Configured() && userEmail != "" {
			msg := mailer.ChangedEmail(userName, sourceIP, time.Now())
			msg.To = userEmail
			if err := m.Send(msg); err != nil {
				log.Warn("password-changed notice failed", zap.Error(err))
			}
		}
		notifySecurityContact(m, userEmail, sourceIP, initiatedBy, log)
	}()

	c.JSON(http.StatusOK, gin.H{
		"ok":      true,
		"message": "Your password has been updated and all existing sessions were signed out. You can now sign in.",
	})
}

// ---------------------------------------------------------------------------
// POST /api/v1/auth/password/change   (authenticated, self-service)
// ---------------------------------------------------------------------------

// handleChangePassword lets a signed-in user rotate their own password.
//
// The current password is required. Without it, an unattended browser or a
// stolen access token converts directly into permanent account ownership, which
// is a strictly worse outcome than the 15-minute window a stolen token otherwise
// gives.
func handleChangePassword(c *gin.Context, store *db.Store, hub *logs.Hub, log *zap.Logger) {
	claims, ok := auth.GetClaims(c.Request.Context())
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
		return
	}
	// An API key authenticates a machine, not a person, and has no password to
	// rotate. Allowing it here would let a leaked key change a human's password.
	if claims.AuthMethod != "password" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "password change requires a password-authenticated session",
		})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "current_password and new_password are required"})
		return
	}
	if problem := validatePassword(req.NewPassword); problem != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": problem})
		return
	}
	if req.NewPassword == req.CurrentPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "the new password must differ from the current one"})
		return
	}

	// Rate-limit by account so this cannot be used to test the current password
	// faster than the login endpoint allows.
	guardKey := "chpw:" + claims.UserID
	if locked, wait := loginAttempts.locked(guardKey); locked {
		c.Header("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())+1))
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many attempts; try again later"})
		return
	}

	valid, err := store.VerifyUserPassword(c.Request.Context(), claims.TenantID, claims.UserID, req.CurrentPassword)
	if err != nil {
		log.Error("password change verification failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not verify the current password"})
		return
	}
	if !valid {
		loginAttempts.recordFailure(guardKey)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is incorrect"})
		return
	}
	loginAttempts.recordSuccess(guardKey)

	if err := store.SetPassword(c.Request.Context(), claims.TenantID, claims.UserID,
		claims.UserID, req.NewPassword); err != nil {
		log.Error("could not change password", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not change the password"})
		return
	}
	sessionEpochs.set(claims.UserID, time.Now().UTC())

	userID := claims.UserID
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &userID,
		Action:      "user.password.change",
		TargetKind:  "user",
		TargetID:    &userID,
	})
	log.Info("console password changed by account holder",
		zap.String("event", "password.change.completed"), zap.String("user_id", userID))

	// The caller's own token was just invalidated along with every other
	// session, so say so plainly rather than letting the UI discover it as a
	// mysterious 401 on the next request.
	c.JSON(http.StatusOK, gin.H{
		"ok":              true,
		"reauth_required": true,
		"message":         "Password updated. All sessions were signed out — please sign in again.",
	})
}

// ---------------------------------------------------------------------------
// POST /api/v1/admin/users/:id/reset-password   (operator-initiated)
// ---------------------------------------------------------------------------

// handleAdminResetPassword lets an administrator start a reset for another user.
//
// It mails that user a link. It does NOT set, return, or display a password:
// an administrator who can read a colleague's new password can impersonate them
// afterwards, and the audit trail would show the colleague acting. The operator
// gets the ability to unblock someone, not the ability to become them.
func handleAdminResetPassword(c *gin.Context, enf *rbac.Enforcer, store *db.Store,
	hub *logs.Hub, log *zap.Logger) {

	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceUser, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database unavailable"})
		return
	}

	targetID := c.Param("id")
	users, err := store.ListUsers(c.Request.Context(), claims.TenantID, claims.UserID)
	if err != nil {
		respondStoreError(c, err)
		return
	}
	var acct db.ResetAccount
	found := false
	for _, u := range users {
		if u.ID == targetID {
			acct = db.ResetAccount{UserID: u.ID, TenantID: u.TenantID, Email: u.Email, Name: u.Name}
			found = true
			break
		}
	}
	// Scoped to the caller's own tenant by construction: ListUsers is
	// tenant-filtered, so an id from another tenant simply is not in the list.
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	m := currentMailer()
	if !m.Config().Configured() {
		// Here the caller IS an authenticated administrator, so telling them the
		// truth is correct and useful — unlike the anonymous endpoint above.
		c.JSON(http.StatusPreconditionFailed, gin.H{
			"error": "SMTP is not configured, so no reset email can be sent. " +
				"Set SENTINEL_SMTP_HOST and SENTINEL_SMTP_FROM on the deployment.",
		})
		return
	}
	if _, err := resetLink(m.Config().PublicURL, "probe"); err != nil {
		c.JSON(http.StatusPreconditionFailed, gin.H{"error": clientError(err)})
		return
	}

	token, expiresAt, err := store.CreateResetToken(c.Request.Context(), acct,
		db.DefaultResetTTL, c.ClientIP(), "admin")
	if err != nil {
		log.Error("admin reset token mint failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not start the reset"})
		return
	}
	link, err := resetLink(m.Config().PublicURL, token)
	if err != nil {
		c.JSON(http.StatusPreconditionFailed, gin.H{"error": clientError(err)})
		return
	}

	if err := sendResetMail(m, acct, link, expiresAt, true, c.ClientIP(), log); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "the reset link could not be emailed; check the SMTP settings",
		})
		return
	}

	actorID := claims.UserID
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &actorID,
		Action:      "user.password.reset_initiated",
		TargetKind:  "user",
		TargetID:    &targetID,
	})

	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"message": fmt.Sprintf("A password reset link was emailed to %s. It expires in %d minutes.",
			acct.Email, int(db.DefaultResetTTL.Minutes())),
	})
}

// ---------------------------------------------------------------------------
// Mail settings (admin)
// ---------------------------------------------------------------------------

// handleMailStatus reports how mail is configured, with the password reduced to
// a boolean so the settings screen can show "set / not set" and never the value.
func handleMailStatus(c *gin.Context, enf *rbac.Enforcer) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceUser, rbac.ActionList) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	cfg := mailer.FromEnv()
	status := cfg.Redacted()
	// Password reset needs BOTH a relay and a link base; report them together so
	// a half-configured deployment is obvious before someone needs it.
	status["password_reset_ready"] = cfg.Configured() && cfg.PublicURL != ""
	if cfg.PublicURL == "" {
		status["public_url_hint"] = "SENTINEL_PUBLIC_URL is not set — reset links cannot be built"
	}
	c.JSON(http.StatusOK, gin.H{"mail": status})
}

// handleMailTest sends a test message so an operator can prove the relay works
// before a user is depending on it.
func handleMailTest(c *gin.Context, enf *rbac.Enforcer, store *db.Store, hub *logs.Hub, log *zap.Logger) {
	claims, _ := auth.GetClaims(c.Request.Context())
	if !enf.Allow(rbac.Role(claims.Role), rbac.ResourceUser, rbac.ActionUpdate) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}
	var req struct {
		To string `json:"to"`
	}
	_ = c.ShouldBindJSON(&req)

	m := currentMailer()
	cfg := m.Config()
	if !cfg.Configured() {
		c.JSON(http.StatusPreconditionFailed, gin.H{
			"error": "SMTP is not configured. Set SENTINEL_SMTP_HOST and SENTINEL_SMTP_FROM.",
		})
		return
	}
	to := strings.TrimSpace(req.To)
	if to == "" {
		to = cfg.NotifyEmail
	}
	if to == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "no recipient: pass \"to\", or set SENTINEL_SECURITY_NOTIFY_EMAIL",
		})
		return
	}

	msg := mailer.TestEmail(osGetenv("SENTINEL_WAF_HOSTNAME", ""))
	msg.To = to
	if err := m.Send(msg); err != nil {
		log.Warn("SMTP test failed", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": "send failed: " + err.Error()})
		return
	}

	actorID := claims.UserID
	writeAuditEntry(c, store, hub, &db.WriteAuditRequest{
		TenantID:    claims.TenantID,
		ActorUserID: &actorID,
		Action:      "settings.mail.test",
		TargetKind:  "settings",
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "Test message sent to " + to})
}
