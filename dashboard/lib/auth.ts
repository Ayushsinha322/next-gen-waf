/**
 * Client-side auth token management for the Sentinel dashboard.
 * Tokens are stored in localStorage (access + refresh).
 * All storage reads/writes are guarded against SSR (typeof window check).
 */

const ACCESS_KEY  = "sentinel_access_token";
const REFRESH_KEY = "sentinel_refresh_token";
const USER_KEY    = "sentinel_user";

export interface AuthUser {
  id:    string;
  email: string;
  role:  string;
}

export interface LoginResponse {
  access_token:  string;
  refresh_token: string;
  expires_in:    number;
  token_type:    string;
  user:          AuthUser;
}

// ---------------------------------------------------------------------------
// Storage helpers (safe in SSR)
// ---------------------------------------------------------------------------
function store(key: string, value: string) {
  if (typeof window !== "undefined") localStorage.setItem(key, value);
}
function read(key: string): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(key);
}
function remove(key: string) {
  if (typeof window !== "undefined") localStorage.removeItem(key);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Returns the current access token or null. */
export function getToken(): string | null {
  return read(ACCESS_KEY);
}

/** Returns the stored user info or null. */
export function getUser(): AuthUser | null {
  const raw = read(USER_KEY);
  if (!raw) return null;
  try { return JSON.parse(raw) as AuthUser; } catch { return null; }
}

/** True when a token is present (does not verify expiry). */
export function isAuthenticated(): boolean {
  return !!read(ACCESS_KEY);
}

/**
 * POST /api/v1/auth/login and persist tokens on success.
 * Throws on HTTP errors.
 */
/** Thrown when the account has TOTP on and no (or no valid) code was supplied.
 *  The control plane answers 401 {mfa_required: true}; the login page catches
 *  this and asks for the code instead of showing a generic failure. */
export class MfaRequiredError extends Error {
  constructor(message = "Enter the 6-digit code from your authenticator app") { super(message); this.name = "MfaRequiredError"; }
}

export async function login(email: string, password: string, mfaCode?: string): Promise<LoginResponse> {
  const res = await fetch("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(mfaCode ? { email, password, mfa_code: mfaCode } : { email, password }),
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    if (res.status === 401 && body.mfa_required === true) throw new MfaRequiredError();
    if (res.status === 401 && typeof body.error === "string" && body.error.includes("mfa code")) {
      throw new MfaRequiredError("That code was not accepted. Codes rotate every 30 seconds — try the current one.");
    }
    throw new Error(body.error ?? "Login failed");
  }

  const data: LoginResponse = await res.json();
  store(ACCESS_KEY,  data.access_token);
  store(REFRESH_KEY, data.refresh_token);
  store(USER_KEY,    JSON.stringify(data.user));
  // Set cookie so Next.js middleware allows page navigations.
  if (typeof document !== "undefined") {
    document.cookie = `sentinel_token=${data.access_token}; path=/; max-age=604800; SameSite=Lax`;
  }
  return data;
}

/** Clear all stored tokens, user info, and the session cookie. */
export function logout() {
  remove(ACCESS_KEY);
  remove(REFRESH_KEY);
  remove(USER_KEY);
  clearSessionCookie();
}

/**
 * Sign out for real: revoke the session on the server, then clear it here.
 *
 * `logout()` above only clears this browser. The control plane has had
 * POST /auth/logout since July, and it does the work that matters — revokes the
 * access token, revokes the PAIRED refresh token via the rjti embedded in the
 * access token, and writes the audit entry that makes a session's span
 * reconstructable. Nothing in the UI ever called it, so "Sign out" left the
 * refresh token valid for its full window and the audit trail recorded logins
 * and never logouts.
 *
 * Best-effort on purpose: a failed revoke must not trap someone in a session
 * they asked to leave, so the local clear always runs.
 *
 * Deliberately separate from `logout()`. The 401 and refresh-failure paths in
 * lib/api.ts call that one, and firing an authenticated request with a token the
 * server has just rejected would either recurse or fail for no benefit. For the
 * same reason the password-change and password-reset flows keep calling
 * `logout()`: both already invalidated every session for the account, so their
 * token is dead before we get here.
 */
export async function signOut(): Promise<void> {
  const token = read(ACCESS_KEY);
  if (token) {
    const refresh = read(REFRESH_KEY);
    try {
      await fetch("/api/v1/auth/logout", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        // The handler also honours an explicitly-supplied refresh token, which
        // covers tokens minted before rjti binding existed.
        body: JSON.stringify(refresh ? { refresh_token: refresh } : {}),
        // The caller navigates away immediately after; without this the request
        // can be cancelled before it is sent, which is exactly the silent
        // no-op this fix exists to remove.
        keepalive: true,
      });
    } catch {
      // Offline, or the control plane is down. Fall through to the local clear.
    }
  }
  logout();
}

/** Expire the sentinel_token cookie immediately. */
export function clearSessionCookie() {
  if (typeof document !== "undefined") {
    document.cookie = "sentinel_token=; path=/; max-age=0; SameSite=Lax";
  }
}

/**
 * Attempt to refresh the access token using the stored refresh token.
 * Updates the stored access token on success.
 * Returns true if refreshed, false if the refresh token is missing/invalid.
 */
export type RefreshOutcome = "ok" | "invalid" | "unavailable";

let refreshInFlight: Promise<RefreshOutcome> | null = null;

/**
 * Renew the access token with the refresh token.
 *
 * "invalid" means the control plane REJECTED the session (401/403: expired,
 * signed out elsewhere, user disabled) — only then is the browser signed out.
 * "unavailable" means the request failed for any other reason: a 5xx while a
 * control-plane node restarts during an upgrade, "cannot verify session" when
 * its database check times out, a network blip. Those used to sign the operator
 * out too, which is how a console tab left open across an upgrade dropped to
 * the login page on its next click. The session is kept; the caller reports the
 * outage and the next request tries again.
 *
 * Concurrent callers share ONE refresh: after an idle tab's access token
 * expires, a page opening fires several requests at once, and each used to
 * start its own refresh.
 */
export function refreshSession(): Promise<RefreshOutcome> {
  if (!refreshInFlight) {
    refreshInFlight = doRefresh().finally(() => { refreshInFlight = null; });
  }
  return refreshInFlight;
}

async function doRefresh(): Promise<RefreshOutcome> {
  const refreshTok = read(REFRESH_KEY);
  if (!refreshTok) return "invalid";
  let res: Response;
  try {
    res = await fetch("/api/v1/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshTok }),
    });
  } catch {
    return "unavailable";
  }
  if (res.status === 401 || res.status === 403) {
    logout();
    return "invalid";
  }
  if (!res.ok) return "unavailable";
  const data = await res.json().catch(() => ({}));
  if (!data.access_token) return "unavailable";
  store(ACCESS_KEY, data.access_token);
  if (typeof document !== "undefined") {
    document.cookie = `sentinel_token=${data.access_token}; path=/; max-age=604800; SameSite=Lax`;
  }
  return "ok";
}

/** Boolean form kept for existing callers: true only when a new token was stored. */
export async function refreshToken(): Promise<boolean> {
  return (await refreshSession()) === "ok";
}
