import { describe, it, expect, vi, afterEach } from "vitest";
import { askCopilot, GREET, COPILOT_MODEL } from "../copilot";

const KEY = "NEXT_PUBLIC_ENLIGHT_API_KEY";

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

describe("askCopilot", () => {
  const orig = process.env[KEY];
  afterEach(() => {
    if (orig === undefined) delete process.env[KEY];
    else process.env[KEY] = orig;
    vi.unstubAllGlobals();
  });

  it("throws (never fabricates) when the API key is unset", async () => {
    delete process.env[KEY];
    await expect(askCopilot([], "hi")).rejects.toThrow(/not configured/i);
  });

  it("sends system prompt + history + user message and returns the model's reply", async () => {
    process.env[KEY] = "test-key";
    const fetchMock = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify({ choices: [{ message: { content: "hello from model" } }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const reply = await askCopilot([{ role: "user", content: "earlier turn" }], "explain this alert");
    expect(reply).toBe("hello from model");
    expect(fetchMock).toHaveBeenCalledOnce();

    const init = fetchMock.mock.calls[0][1] as RequestInit;
    const body = JSON.parse(init.body as string);
    expect(body.model).toMatch(/deepseek/i);
    expect(body.messages[0].role).toBe("system");
    expect(body.messages).toContainEqual({ role: "user", content: "earlier turn" });
    expect(body.messages.at(-1)).toEqual({ role: "user", content: "explain this alert" });
  });

  it("throws on a non-ok response instead of inventing an answer", async () => {
    process.env[KEY] = "test-key";
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: { message: "boom" } }), { status: 500 })),
    );
    await expect(askCopilot([], "hi")).rejects.toThrow(/500/);
  });
});
