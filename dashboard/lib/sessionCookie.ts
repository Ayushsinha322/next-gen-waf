/**
 * The console's session cookie — a MARKER, never a credential.
 *
 * Its only reader is middleware.ts, which uses it to let page navigations
 * through (the API authenticates every call with the Authorization header).
 * Until 1.1.11 its value was the admin's access token, and that mattered more
 * than it looks: browsers scope cookies by host, not port, so a console at
 * https://host:9443 sent this cookie to every site the WAF served on that
 * host — over plain HTTP, readable by the site's own scripts. One XSS in any
 * protected app was a WAF-admin session. Found 2026-09-26 in the redacted
 * request headers of a Juice Shop event.
 *
 * Now it holds `active`, is `Secure` whenever the console is served over HTTPS,
 * and the data plane strips it from every request it forwards to an origin.
 * The token itself stays in localStorage, which is isolated per ORIGIN (port
 * included), so no page on another port can read it.
 *
 * No browser globals at module scope: the Edge-runtime middleware imports this.
 */
export const SESSION_COOKIE = "sentinel_token";
export const SESSION_MARKER = "active";
const MAX_AGE_SECONDS = 7 * 24 * 3600; // matches the refresh token's lifetime

export function sessionCookieString(https: boolean): string {
  return `${SESSION_COOKIE}=${SESSION_MARKER}; path=/; max-age=${MAX_AGE_SECONDS}; SameSite=Lax${https ? "; Secure" : ""}`;
}

/** Mark this browser as signed in (client only). */
export function setSessionCookie(): void {
  if (typeof document === "undefined") return;
  document.cookie = sessionCookieString(typeof location !== "undefined" && location.protocol === "https:");
}

/**
 * Does this cookie value mean "signed in" to the navigation gate? The marker,
 * or — for a browser still holding a cookie from an older console — anything
 * JWT-shaped. That older value is overwritten at the next token refresh
 * (at most 15 minutes), so it ages out on its own.
 */
export function isSessionCookieValue(value: string | undefined): boolean {
  if (!value) return false;
  if (value === SESSION_MARKER) return true;
  const parts = value.split(".");
  if (parts.length !== 3) return false;
  try {
    JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    return true;
  } catch {
    return false;
  }
}
