/**
 * Safe rendering for the small markdown subset the Copilot emits.
 *
 * SECURITY: Copilot replies are NOT trusted input. The assistant routinely
 * quotes attacker-controlled data back to the operator — "explain the latest
 * alert" makes it echo the offending request's User-Agent, path, and payload.
 * An attacker therefore only has to send one request through the data plane
 * with a script in a header to get that script into the admin's chat pane.
 *
 * So every transform here runs on ALREADY-ESCAPED text: `escapeHtml` first,
 * markup after. The only tags in the output are the ones this module emits.
 * Never reorder that. If you need a new markdown feature, add it below the
 * escape step, never above it.
 */

/** Escape the five characters that let text break out of HTML content. */
export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Placeholder for extracted fenced blocks. It deliberately contains "<": by the
// time it is inserted, escapeHtml has turned any "<" from the input into "&lt;",
// so this token cannot be forged by the text being rendered.
const BLOCK_OPEN = "<<<sentinel:block:";
const BLOCK_CLOSE = ">>>";

/**
 * Render the Copilot's markdown subset (fenced blocks, inline code, bold,
 * newlines) to HTML that is safe to hand to `dangerouslySetInnerHTML`.
 */
export function renderCopilotMarkdown(text: string): string {
  const blocks: string[] = [];

  // Fenced blocks are pulled out before anything else so that (a) their
  // contents are never treated as inline markup and (b) their newlines survive
  // for `white-space: pre-wrap` instead of being turned into <br>.
  let out = escapeHtml(text).replace(/```([\s\S]*?)```/g, (_match, code: string) => {
    blocks.push(code);
    return `${BLOCK_OPEN}${blocks.length - 1}${BLOCK_CLOSE}`;
  });

  out = out
    .replace(/`([^`\n]+)`/g, '<code class="cp-code">$1</code>')
    .replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\n/g, "<br>");

  return out.replace(
    /<<<sentinel:block:(\d+)>>>/g,
    (_match, index: string) => `<pre class="cp-pre">${blocks[Number(index)] ?? ""}</pre>`,
  );
}
