import { describe, it, expect, beforeEach, vi } from "vitest";

// Minimal browser surface for lib/auth.ts in the Node test environment.
const mem = new Map<string, string>();
beforeEach(() => {
  mem.clear();
  (globalThis as Record<string, unknown>).window = {};
  (globalThis as Record<string, unknown>).localStorage = {
    getItem: (k: string) => mem.get(k) ?? null,
    setItem: (k: string, v: string) => void mem.set(k, v),
    removeItem: (k: string) => void mem.delete(k),
  };
  (globalThis as Record<string, unknown>).document = { cookie: "" };
  vi.resetModules();
});

async function withRefreshToken() {
  const auth = await import("../auth");
  // Seed a session the way login() stores it, without calling the network.
  mem.set("sentinel_refresh_token", "r.e.f");
  return auth;
}

function stubFetch(impl: () => Promise<Response>) {
  const f = vi.fn(impl);
  (globalThis as Record<string, unknown>).fetch = f;
  return f;
}

describe("refreshSession only signs out when the session is REJECTED", () => {
  it("a 503 (control plane restarting / cannot verify session) keeps the session", async () => {
    const auth = await withRefreshToken();
    const before = [...mem.keys()];
    stubFetch(async () => new Response('{"error":"cannot verify session"}', { status: 503 }));
    expect(await auth.refreshSession()).toBe("unavailable");
    expect([...mem.keys()]).toEqual(before);
  });

  it("a network failure keeps the session", async () => {
    const auth = await withRefreshToken();
    stubFetch(async () => { throw new TypeError("Failed to fetch"); });
    expect(await auth.refreshSession()).toBe("unavailable");
    expect(mem.size).toBeGreaterThan(0);
  });

  it("a 401 is a real rejection: signed out", async () => {
    const auth = await withRefreshToken();
    stubFetch(async () => new Response('{"error":"invalid refresh token"}', { status: 401 }));
    expect(await auth.refreshSession()).toBe("invalid");
  });

  it("concurrent callers share ONE refresh request", async () => {
    const auth = await withRefreshToken();
    const f = stubFetch(async () => new Response('{"access_token":"a.b.c"}', { status: 200 }));
    const out = await Promise.all([auth.refreshSession(), auth.refreshSession(), auth.refreshSession()]);
    expect(out).toEqual(["ok", "ok", "ok"]);
    expect(f).toHaveBeenCalledTimes(1);
  });
});
