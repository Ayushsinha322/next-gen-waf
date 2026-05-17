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

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Allow public paths.
  if (PUBLIC_PATHS.some(p => pathname.startsWith(p))) {
    return NextResponse.next();
  }

  // Check for access token in cookies (set by the login page after auth).
  const token = request.cookies.get("sentinel_token")?.value;
  if (!token || !isValidJWT(token)) {
    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = "/login";
    // Expire the stale cookie in the response so the browser drops it.
    const res = NextResponse.redirect(loginUrl);
    res.cookies.set("sentinel_token", "", { path: "/", maxAge: 0 });
    return res;
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|public/).*)"],
};
