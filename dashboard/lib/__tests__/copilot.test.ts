import { describe, it, expect, vi, afterEach } from "vitest";
import { askCopilot, GREET, COPILOT_MODEL } from "../copilot";

describe("GREET", () => {
  it("contains no fabricated statistics", () => {
    // Regression guard for the old canned copilot: it quoted invented numbers
    // like "2,847,293 requests" and "0.003% FP". None of that may reappear here.
    expect(GREET).not.toMatch(/\d{1,3}(,\d{3})+/); // comma-grouped counts
    expect(GREET).not.toMatch(/\d+(\.\d+)?\s*%/); // percentages
    expect(GREET).not.toMatch(/\brequests?\b/i);
  });

  it("names the real backing model", () => {
    expect(GREET).toMatch(/DeepSeek/i);
    expect(COPILOT_MODEL).toMatch(/deepseek/i);
  });
});

describe("askCopilot (client)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("never sends a credential or contacts the gateway directly", async () => {
    // The gateway key must stay server-side. The browser may only ever talk to
    // our own same-origin proxy.
    const fetchMock = vi.fn(
      async (_url: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ reply: "ok" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await askCopilot([], "hi");

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("/api/copilot");
    expect(url).not.toMatch(/^https?:\/\//);
    const headers = (init.headers ?? {}) as Record<string, string>;
    expect(Object.keys(headers).map(h => h.toLowerCase())).not.toContain("authorization");
    expect(JSON.stringify(init)).not.toMatch(/Bearer/);
  });

  it("forwards history and the new message, and returns the reply", async () => {
    const fetchMock = vi.fn(
      async (_url: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ reply: "hello from model" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const reply = await askCopilot([{ role: "user", content: "earlier turn" }], "explain this alert");
    expect(reply).toBe("hello from model");

    const init = fetchMock.mock.calls[0][1] as RequestInit;
    const body = JSON.parse(init.body as string);
    expect(body.history).toContainEqual({ role: "user", content: "earlier turn" });
    expect(body.text).toBe("explain this alert");
  });

  it("throws the server's error instead of inventing an answer", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ error: "Copilot is not configured — ENLIGHT_API_KEY is unset." }), {
            status: 502,
          }),
      ),
    );
    await expect(askCopilot([], "hi")).rejects.toThrow(/not configured/i);
  });

  it("throws on a malformed success payload rather than returning undefined", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ nonsense: true }), { status: 200 })),
    );
    await expect(askCopilot([], "hi")).rejects.toThrow(/Unexpected response format/);
  });
});
