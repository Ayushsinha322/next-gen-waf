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
export async function login(email: string, password: string): Promise<LoginResponse> {
  const res = await fetch("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
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
export async function refreshToken(): Promise<boolean> {
  const refreshTok = read(REFRESH_KEY);
  if (!refreshTok) return false;

  const res = await fetch("/api/v1/auth/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshTok }),
  });
  if (!res.ok) {
    logout();
    return false;
  }
  const data = await res.json();
  if (data.access_token) {
    store(ACCESS_KEY, data.access_token);
    if (typeof document !== "undefined") {
      document.cookie = `sentinel_token=${data.access_token}; path=/; max-age=604800; SameSite=Lax`;
    }
    return true;
  }
  return false;
}
