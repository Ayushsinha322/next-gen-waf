// Formatting for the control plane's p99 latency figures.
//
// A p99 is a measurement only when it was computed from samples. The control
// plane's latency rings hold the last five minutes of access-log rows, so they
// are empty after a restart and on any site that has been quiet for five
// minutes — and then it reports p99 0 with 0 samples. Printing that 0 as
// "0.0 ms" presents the ABSENCE of a measurement as the best possible one. The
// top bar and the Overview each learned this on their own; the Traffic page did
// not, and read "p99 Latency 0.0 ms" while the rest of the console said "—".
//
// There are also two different p99s, and a card has to say which one it shows:
//   p99_latency_ms  END-TO-END, including the wait on the origin
//   p99_waf_ms      the WAF's OWN processing time (what the top-bar badge shows)
// A slow origin moves only the first.

/** "—" when nothing was measured, otherwise the value in ms. */
export function formatP99(ms: number | null | undefined, samples: number | null | undefined, digits = 1): string {
  if (ms == null || !Number.isFinite(ms) || ms < 0) return "—";
  // A control plane older than the sample count reports only the value; there,
  // 0 is the one reading that can only mean "no samples".
  if (samples === 0 || (samples == null && ms === 0)) return "—";
  return ms < 0.1 ? "<0.1 ms" : `${ms.toFixed(digits)} ms`;
}
