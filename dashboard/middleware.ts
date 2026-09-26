import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { SESSION_COOKIE, isSessionCookieValue } from "@/lib/sessionCookie";

// Password recovery has to be reachable by someone who cannot sign in, so these
// two routes are public alongside the login page. They carry no data of their
// own: /forgot-password only submits an address, and /reset-password is useless
// without a token the server independently validates.
const PUBLIC_PATHS = ["/login", "/forgot-password", "/reset-password", "/api/"];


/**
 * Build the Content-Security-Policy for this response.
 *
 * This is defence-in-depth behind output escaping, not a replacement for it: the
 * dashboard's own XSS sinks are fixed at the source (`escHtml` in the logs
 * view). The policy exists so that the
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

  // The log stream is SAME-ORIGIN by default (see lib/api.ts logs.streamURL),
  // so 'self' already covers it and connect-src stays as tight as possible.
  // This only widens when NEXT_PUBLIC_CONTROL_PLANE_URL is explicitly set to
  // point the stream at a different origin — the :3000 break-glass path, where
  // Next's rewrite buffers SSE. Unset (the normal case) → no extra origin.
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

  // The session marker cookie (lib/sessionCookie.ts) — a gate for page
  // navigations only; every API call is authenticated by its own header.
  const token = request.cookies.get(SESSION_COOKIE)?.value;
  if (!isSessionCookieValue(token)) {
    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = "/login";
    // Expire the stale cookie in the response so the browser drops it.
    const res = applyTo(NextResponse.redirect(loginUrl));
    res.cookies.set(SESSION_COOKIE, "", { path: "/", maxAge: 0 });
    return res;
  }

  return applyTo(NextResponse.next(forward));
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|public/).*)"],
};
