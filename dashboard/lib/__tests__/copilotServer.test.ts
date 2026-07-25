import { describe, it, expect, vi, afterEach } from "vitest";
import { generateReply, COPILOT_ENDPOINT } from "../copilotServer";

const KEY = "ENLIGHT_API_KEY";

describe("generateReply (server)", () => {
  const orig = process.env[KEY];
  afterEach(() => {
    if (orig === undefined) delete process.env[KEY];
    else process.env[KEY] = orig;
    vi.unstubAllGlobals();
  });

  it("reads a server-only env var, never a NEXT_PUBLIC_ one", () => {
    // NEXT_PUBLIC_* is inlined into the browser bundle by Next.js, so the
    // gateway credential must not be named that way. This guards the fix.
    const source = generateReply.toString();
    expect(source).not.toMatch(/NEXT_PUBLIC_/);
  });

  it("throws (never fabricates) when the API key is unset", async () => {
    delete process.env[KEY];
    await expect(generateReply([], "hi")).rejects.toThrow(/not configured/i);
  });

  it("sends system prompt + history + user message and returns the model's reply", async () => {
    process.env[KEY] = "test-key";
    const fetchMock = vi.fn(
      async (_url: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ choices: [{ message: { content: "hello from model" } }] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const reply = await generateReply([{ role: "user", content: "earlier turn" }], "explain this alert");
    expect(reply).toBe("hello from model");
    expect(fetchMock).toHaveBeenCalledOnce();

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(COPILOT_ENDPOINT);
    const body = JSON.parse(init.body as string);
    expect(body.model).toMatch(/deepseek/i);
    expect(body.messages[0].role).toBe("system");
    expect(body.messages).toContainEqual({ role: "user", content: "earlier turn" });
    expect(body.messages.at(-1)).toEqual({ role: "user", content: "explain this alert" });
  });

  it("authenticates to the gateway with the server-side key", async () => {
    process.env[KEY] = "test-key";
    const fetchMock = vi.fn(
      async (_url: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ choices: [{ message: { content: "x" } }] }), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await generateReply([], "hi");
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer test-key");
  });

  it("throws on a non-ok response instead of inventing an answer", async () => {
    process.env[KEY] = "test-key";
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: { message: "boom" } }), { status: 500 })),
    );
    await expect(generateReply([], "hi")).rejects.toThrow(/500/);
  });

  it("does not leak the key in error messages", async () => {
    process.env[KEY] = "super-secret-key";
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: { message: "boom" } }), { status: 500 })),
    );
    await expect(generateReply([], "hi")).rejects.toThrow(
      expect.objectContaining({ message: expect.not.stringContaining("super-secret-key") }),
    );
  });
});
