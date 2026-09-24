import { describe, it, expect, vi, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { askCopilot, greetingFor, type CopilotStatus } from "../copilot";

const ALL: CopilotStatus[] = [
  { kind: "checking" },
  { kind: "ready", model: "some-model:7b" },
  { kind: "unconfigured" },
  { kind: "unreachable" },
];

describe("greetingFor", () => {
  it("contains no fabricated statistics in any state", () => {
    // Regression guard for the old canned copilot: it quoted invented numbers
    // like "2,847,293 requests" and "0.003% FP". None of that may reappear here.
    for (const s of ALL) {
      const g = greetingFor(s);
      expect(g).not.toMatch(/\d{1,3}(,\d{3})+/); // comma-grouped counts
      expect(g).not.toMatch(/\d+(\.\d+)?\s*%/); // percentages
      expect(g).not.toMatch(/\brequests?\b/i);
    }
  });

  it("names the model the server reported, and only then", () => {
    expect(greetingFor({ kind: "ready", model: "some-model:7b" })).toContain("some-model:7b");
    for (const s of ALL.filter(s => s.kind !== "ready")) {
      expect(greetingFor(s)).not.toMatch(/powered by|running on|deepseek/i);
    }
  });

  it("offers help only when there is a model to give it", () => {
    // The unconfigured console used to greet with "I can help: …" above a
    // status line reading "Not configured"; every question then failed.
    expect(greetingFor({ kind: "ready", model: "m" })).toMatch(/I can help/);
    expect(greetingFor({ kind: "unconfigured" })).toMatch(/not configured/i);
    expect(greetingFor({ kind: "unconfigured" })).not.toMatch(/I can help/);
    expect(greetingFor({ kind: "unreachable" })).not.toMatch(/I can help/);
  });

  it("no client file hard-codes a model name", () => {
    // The model lives in lib/copilotServer.ts and reaches the browser only via
    // GET /api/copilot. The page and the floating panel each carried a literal
    // "deepseek-r1:8b" badge and a "Powered by DeepSeek R1" line.
    const root = join(__dirname, "../..");
    for (const f of ["lib/copilot.ts", "app/(dashboard)/copilot/page.tsx", "components/copilot/CopilotFab.tsx", "components/copilot/CopilotStatus.tsx"]) {
      const code = readFileSync(join(root, f), "utf8").split("\n").filter(l => !/^\s*(\/\/|\*)/.test(l)).join("\n");
      expect(code, f).not.toMatch(/deepseek/i);
    }
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
