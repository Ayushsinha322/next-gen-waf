export const AI_RESPONSES: Record<string, string> = {
  explain: "**SQL Injection Detected** at `/api/login`\n\nRule `CRS-942100` matched `UNION SELECT` in param `id`.\nSource: `185.220.101.45` (Tor Exit Node)\nAnomaly Score: **24/50** — threshold exceeded.\n\n✅ Action: Terminated + IP flagged for 24h.",
  rule: "Here's a custom SRL rule to block scanners:\n\n```\nrule block-scanners {\n  id: 9000001\n  phase: request_headers\n  target: REQUEST_HEADERS:User-Agent\n  operator: rx('/sqlmap|nikto|nmap|nuclei/i')\n  action: block\n  severity: critical\n}\n```",
  report: "**24-Hour Summary**\n\n• 2,847,293 total requests\n• 3,204 threats blocked (0.11%)\n• Top attacks: SQLi 48% · XSS 27% · Path Traversal 15%\n• ML detections: **89** (82 confirmed)\n• False positive rate: **0.003%** ✅",
  fp: "**False Positive Fix**\n\nRule `CRS-920420` may trigger on API clients with multiple `Content-Type` headers.\n\n**Fix:**\n```yaml\nwaf:\n  exceptions:\n    - rule_id: 920420\n      path_prefix: /api/\n```",
  patch: "Share the CVE ID (e.g. `CVE-2024-12345`) and description — I'll generate a Sentinel SRL virtual patch deployable instantly with zero restart.",
  tune: "**ML Threshold Tuning**\n\nCurrent sensitivity: `0.85`. Suggested adjustments based on recent traffic:\n\n• Lower to `0.80` for API-heavy sites (reduces false positives)\n• Increase to `0.90` during high-risk periods\n• Use `sentinel copilot tune --site dvwa.local` to apply\n\nLast 7d false positive rate: **0.003%** ✅",
};
export const GREET = "Hello! I'm **Sentinel AI Copilot** — powered by DeepSeek R1.\n\nI can help:\n• 🔍 Explain security alerts\n• 📝 Generate SRL WAF rules\n• 🛡️ Create CVE virtual patches\n• 🐛 Debug false positives\n• 📊 Security reports\n\nWhat would you like to know?";
export function getAIResponse(text: string): string {
  const l = text.toLowerCase();
  if (l.includes("rule") || l.includes("srl")) return AI_RESPONSES.rule;
  if (l.includes("report") || l.includes("summary")) return AI_RESPONSES.report;
  if (l.includes("false") || l.includes("fp") || l.includes("positive")) return AI_RESPONSES.fp;
  if (l.includes("cve") || l.includes("patch")) return AI_RESPONSES.patch;
  if (l.includes("tune") || l.includes("ml") || l.includes("threshold")) return AI_RESPONSES.tune;
  return AI_RESPONSES.explain;
}
