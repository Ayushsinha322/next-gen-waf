import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const PUBLIC_PATHS = ["/login", "/api/"];

function isValidJWT(token: string): boolean {
  // A JWT has exactly 3 base64url segments separated by dots.
  // We only check structure here — the Go API enforces actual expiry on every
  // request, and the client silently refreshes the access token via refreshToken().
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  try {
    JSON.parse(Buffer.from(parts[1], "base64").toString("utf8"));
    return true;
  } catch {
    return false;
  }
}

/**
 * Build the Content-Security-Policy for this response.
 *
 * This is defence-in-depth behind output escaping, not a replacement for it: the
 * dashboard's own XSS sinks are fixed at the source (lib/safeMarkdown.ts for
 * Copilot output, `escHtml` in the logs view). The policy exists so that the
 * *next* injection bug is contained rather than immediately exploitable.
 *
 * `script-src` is nonce-based with 'strict-dynamic'. Next.js reads the nonce
 * from the Content-Security-Policy request header we set below and applies it to
 * the scripts it injects; 'strict-dynamic' then covers the chunks those scripts
 * load. The one hand-written inline script (the FOUC theme setter in
 * app/layout.tsx) reads the same nonce from the x-nonce request header.
 *
 * `style-src` must keep 'unsafe-inline'. The UI styles almost everything through
 * React `style={{...}}` props and framer-motion animates via inline styles, and
 * CSP's style-src governs style attributes as well as <style> blocks. Removing
 * it means porting every inline style to a class — worth doing, but it is a
 * large refactor and not a prerequisite for closing the XSS. Note that
 * 'unsafe-inline' in style-src does NOT permit script execution.
 */
function buildCSP(nonce: string): string {
  const isDev = process.env.NODE_ENV !== "production";

  // The log stream is a cross-origin EventSource straight to the Go control
  // plane (see lib/api.ts logs.streamURL) because the Next proxy buffers SSE, so
  // connect-src has to allow that origin explicitly.
  const controlPlane = process.env.NEXT_PUBLIC_CONTROL_PLANE_URL ?? "";
  let controlPlaneOrigin = "";
  try {
    if (controlPlane) controlPlaneOrigin = new URL(controlPlane).origin;
  } catch {
    controlPlaneOrigin = "";
  }

  const scriptSrc = ["'self'", `'nonce-${nonce}'`, "'strict-dynamic'"];
  // React Refresh / HMR compiles with eval in dev only. Never in production.
  if (isDev) scriptSrc.push("'unsafe-eval'");

  const connectSrc = ["'self'", controlPlaneOrigin].filter(Boolean);
  // Dev server websocket for hot reload.
  if (isDev) connectSrc.push("ws:", "wss:");

  return [
    "default-src 'self'",
    `script-src ${scriptSrc.join(" ")}`,
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: blob:",
    `connect-src ${connectSrc.join(" ")}`,
    // No plugins, no framing of this app, no <base> hijacking, and forms may
    // only post back to us.
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ");
}

/** Security headers applied to every response, CSP included. */
function securityHeaders(nonce: string): Record<string, string> {
  return {
    "Content-Security-Policy": buildCSP(nonce),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    // Legacy header, still honoured by some proxies/older browsers.
    "X-Frame-Options": "DENY",
    // The dashboard needs none of these device capabilities.
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  };
}

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const nonce = crypto.randomUUID();
  const headers = securityHeaders(nonce);

  const applyTo = (res: NextResponse) => {
    for (const [k, v] of Object.entries(headers)) res.headers.set(k, v);
    return res;
  };

  // Next.js extracts the nonce for its own injected scripts from the CSP on the
  // *request*; app/layout.tsx reads x-nonce for the inline theme script.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", headers["Content-Security-Policy"]);
  const forward = { request: { headers: requestHeaders } };

  // Allow public paths.
  if (PUBLIC_PATHS.some(p => pathname.startsWith(p))) {
    return applyTo(NextResponse.next(forward));
  }

  // Check for access token in cookies (set by the login page after auth).
  const token = request.cookies.get("sentinel_token")?.value;
  if (!token || !isValidJWT(token)) {
    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = "/login";
    // Expire the stale cookie in the response so the browser drops it.
    const res = applyTo(NextResponse.redirect(loginUrl));
    res.cookies.set("sentinel_token", "", { path: "/", maxAge: 0 });
    return res;
  }

  return applyTo(NextResponse.next(forward));
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|public/).*)"],
};
