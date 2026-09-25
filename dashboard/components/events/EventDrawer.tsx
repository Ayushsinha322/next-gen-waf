"use client";
/**
 * Security-event detail drawer.
 *
 * Why this exists: a Sentinel security event used to be a dead end. The events
 * table was ten read-only columns with no row click, so an operator could see
 * THAT a request was blocked but never why, and could do nothing about it
 * without leaving for the Sites screen and hand-editing a policy. Every
 * competitor — F5, Imperva, Cloudflare, and free open-source BunkerWeb — opens
 * a blocked request and offers remediation in place. This closes that gap.
 *
 * What the stored event carries (crates/sentinel-storage/src/clickhouse.rs
 * WafEventRow): the leading rule and its matched text, EVERY contributing rule
 * with its own score (`rules`, since 2026-09-25), the parameter where the data
 * plane could be certain (`target` — "" or a collection name when it could not),
 * and the redacted request headers and User-Agent. Rows stored before those
 * columns have none of them, and this drawer shows nothing rather than implying
 * evidence it lacks. No response body is stored.
 */
import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { api, type WafEvent, type EventRule, type Site } from "@/lib/api";
import { showToast } from "@/components/ui/Toast";

function Row({ label, children, mono = false }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "132px 1fr", gap: 12, padding: "7px 0", borderBottom: "1px solid var(--border2)" }}>
      <div style={{ fontSize: "var(--fs-label)", color: "var(--text3)", textTransform: "uppercase", letterSpacing: "var(--tr-wide)" }}>{label}</div>
      <div style={{ fontSize: "var(--fs-sm)", color: "var(--text)", fontFamily: mono ? "var(--font-mono)" : undefined, overflowWrap: "anywhere" }}>{children}</div>
    </div>
  );
}

export default function EventDrawer({
  event, sites, onClose,
}: {
  event: WafEvent | null;
  sites: Site[];
  onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);

  // Escape closes, matching every drawer pattern operators already know.
  useEffect(() => {
    if (!event) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [event, onClose]);

  if (!event) return null;

  // The exclusion API is keyed by site id; the event only carries the site name.
  const site = sites.find(s => s.name === event.site || s.domains?.includes(event.site));
  const ruleId = Number.parseInt(event.rule, 10);
  const ruleIsNumeric = Number.isFinite(ruleId) && ruleId > 0;

  async function addExclusion() {
    if (!site || !ruleIsNumeric) return;
    setBusy(true);
    try {
      await api.sites.addExclusion(site.id, { rule_id: ruleId, disable: true });
      showToast(`Rule ${ruleId} excluded on ${site.name}`, "s");
      onClose();
    } catch (e) {
      showToast(e instanceof Error ? e.message : "Could not add exclusion", "e");
    } finally {
      setBusy(false);
    }
  }

  const copyJson = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(event, null, 2));
      showToast("Event copied as JSON", "s");
    } catch {
      showToast("Clipboard unavailable", "e");
    }
  };

  const sev = event.severity?.toUpperCase() ?? "";
  const sevClass = sev === "CRITICAL" ? "br" : sev === "HIGH" ? "ba" : "bcy";

  return (
    <AnimatePresence>
      <motion.div
        key="scrim"
        initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        transition={{ duration: 0.15 }}
        onClick={onClose}
        style={{ position: "fixed", inset: 0, zIndex: 900, background: "rgba(2,6,14,.6)" }}
      />
      <motion.aside
        key="drawer"
        role="dialog"
        aria-modal="true"
        aria-label="Security event detail"
        initial={{ x: "100%" }} animate={{ x: 0 }} exit={{ x: "100%" }}
        transition={{ type: "spring", stiffness: 380, damping: 38 }}
        onClick={e => e.stopPropagation()}
        style={{
          position: "fixed", top: 0, right: 0, bottom: 0, zIndex: 901,
          width: "min(560px, 96vw)", background: "var(--bg2)",
          borderLeft: "1px solid var(--border2)", boxShadow: "-8px 0 32px rgba(0,0,0,.4)",
          display: "flex", flexDirection: "column",
        }}
      >
        <header style={{ padding: "16px 20px", borderBottom: "1px solid var(--border2)", display: "flex", alignItems: "flex-start", gap: 12 }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span className={`bdg ${event.action === "BLOCK" ? "br" : "ba"}`}>{event.action}</span>
              {sev && <span className={`bdg ${sevClass}`}>{sev}</span>}
            </div>
            <div style={{ fontSize: "var(--fs-h2)", fontWeight: 600, color: "var(--text)", marginTop: 8 }}>
              {event.attack || "Security event"}
            </div>
          </div>
          <button className="btn bg-btn btn-sm" onClick={onClose} aria-label="Close">✕</button>
        </header>

        <div style={{ flex: 1, overflowY: "auto", padding: "8px 20px 20px" }}>
          {/* Lead with the WAF's own explanation. It states what was detected,
              where, why the verdict followed and whether it was ENFORCED — the
              questions an operator opens this drawer to answer. Absent on events
              recorded before the explain-the-verdict change, in which case the
              structured fields below still tell the story. */}
          {event.explanation && (
            <div
              style={{
                margin: "12px 0 4px", padding: "12px 14px", borderRadius: 8,
                border: "1px solid var(--border2)", background: "var(--bg3)",
                fontSize: "var(--fs-sm)", lineHeight: 1.65, color: "var(--text2)",
              }}
            >
              {event.explanation}
              {event.mode && event.mode !== "blocking" && (
                <div style={{ marginTop: 8, color: "var(--amber)" }}>
                  Site mode at the time: <strong>{event.mode}</strong>
                  {event.mode === "learning" && " — this request was NOT blocked."}
                </div>
              )}
            </div>
          )}
          {/* Local time first — it is what the customer quoting the Support ID
              saw — and UTC beside it, which is what the Logs page and exports use. */}
          <Row label="Time" mono>
            {new Date(event.ts * 1000).toLocaleString()}
            <span style={{ color: "var(--text3)" }}> · {new Date(event.ts * 1000).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC")}</span>
          </Row>
          <Row label="Source IP" mono>{event.ip}{event.country ? ` · ${event.country}` : ""}</Row>
          <Row label="Site" mono>{event.site}</Row>
          <Row label="Request" mono>{event.method} {event.path}{event.query ? `?${event.query}` : ""}</Row>
          {event.referer && <Row label="Referer" mono>{event.referer}</Row>}
          <Row label="Protocol" mono>{event.protocol || "—"}</Row>
          {/* The TLS fingerprint behind a bot verdict. Shown only when present:
              plaintext requests and rows older than the column have none, and a
              placeholder here would read as "the WAF failed to fingerprint". */}
          {event.ja4 && <Row label="JA4" mono>{event.ja4}</Row>}
          {event.ua && <Row label="User-Agent" mono>{event.ua}</Row>}
          <Row label="Response" mono>{event.status || "—"}</Row>
          <Row label="Matched rule" mono>{event.rule || "—"}</Row>
          <Row label="Anomaly score" mono>{event.score}</Row>
          {/* The Support ID the visitor was shown. Click-to-copy because the
              operator reads it back to the customer to confirm they are talking
              about the same request. Older rows predate the field. */}
          <Row label="Support ID" mono>
            {event.request_id ? (
              <span
                title="Click to copy — this is the ID shown on the block page"
                style={{ cursor: "pointer", userSelect: "all" }}
                onClick={() => {
                  navigator.clipboard.writeText(event.request_id).then(
                    () => showToast("Support ID copied", "s"),
                    () => {},
                  );
                }}
              >{event.request_id}</span>
            ) : "—"}
          </Row>

          {/* The payload the rule matched — what lets an operator judge a false
              positive from this drawer alone. Absent on rows written before the
              column existed, or when the operator produced no capturable text;
              credential-bearing targets arrive already redacted by the data
              plane, so a raw password can never render here. */}
          {event.matched ? (
            <div style={{
              marginTop: 16, padding: "10px 12px", borderRadius: "var(--r2)",
              background: "var(--bg3)", border: "1px solid var(--border2)",
            }}>
              <div style={{ fontSize: "var(--fs-label)", color: "var(--text3)", textTransform: "uppercase", letterSpacing: "var(--tr-wide)", marginBottom: 6 }}>
                Matched payload{event.target ? ` — ${event.target}` : ""}
              </div>
              <code style={{
                fontFamily: "var(--font-mono)", fontSize: "var(--fs-sm)",
                color: "var(--text)", wordBreak: "break-all", whiteSpace: "pre-wrap",
              }}>{event.matched}</code>
            </div>
          ) : (
            <div style={{
              marginTop: 16, padding: "10px 12px", borderRadius: "var(--r2)",
              background: "var(--bg3)", border: "1px solid var(--border2)",
              fontSize: "var(--fs-label)", color: "var(--text3)", lineHeight: 1.6,
            }}>
              No matched payload was recorded for this event — either it predates
              payload capture, or the operator that fired produced no capturable
              text (numeric comparisons, validators, classifier verdicts).
            </div>
          )}

          {event.rules && event.rules.length > 0 && <MatchedRules rules={event.rules} score={event.score} />}
          {event.headers && Object.keys(event.headers).length > 0 && <RequestHeaders headers={event.headers} />}

          <div style={{ marginTop: 20 }}>
            <div style={{ fontSize: "var(--fs-label)", color: "var(--text3)", textTransform: "uppercase", letterSpacing: "var(--tr-wide)", marginBottom: 10 }}>
              Remediation
            </div>

            {!site && (
              <div style={{ fontSize: "var(--fs-sm)", color: "var(--text3)", marginBottom: 10 }}>
                No site in this tenant matches <code style={{ fontFamily: "var(--font-mono)" }}>{event.site}</code>, so
                policy actions are unavailable for this event.
              </div>
            )}

            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              <button
                className="btn bg-btn btn-sm"
                disabled={!site || !ruleIsNumeric || busy}
                title={
                  !site ? "Site not found in this tenant"
                    : !ruleIsNumeric ? "This event has no numeric rule id to exclude"
                    : `Stop rule ${ruleId} from firing on ${site.name}`
                }
                onClick={addExclusion}
              >
                {busy ? "Applying…" : `Exclude rule ${ruleIsNumeric ? ruleId : ""} on this site`}
              </button>
              <button className="btn bg-btn btn-sm" onClick={copyJson}>Copy event JSON</button>
            </div>

            <div style={{ fontSize: "var(--fs-label)", color: "var(--text3)", marginTop: 10, lineHeight: 1.6 }}>
              Excluding a rule disables it for this site only, and takes effect on the
              next config sync. It is the right fix for a confirmed false positive and
              the wrong one for a real detection — there is no per-IP block action here
              because the data plane has no API to add or release one.
            </div>
          </div>
        </div>
      </motion.aside>
    </AnimatePresence>
  );
}

const sectionLabel: React.CSSProperties = {
  fontSize: "var(--fs-label)", color: "var(--text3)", textTransform: "uppercase",
  letterSpacing: "var(--tr-wide)", marginBottom: 8,
};

/**
 * Every rule that added to the score. The event used to name only the leading
 * rule, so an anomaly score of 85 read as one rule's doing — and excluding that
 * rule for a false positive left the others still over the threshold. The sum
 * can fall short of the anomaly score: the ML engine and IP history contribute
 * too, and they are not rules.
 */
function MatchedRules({ rules, score }: { rules: EventRule[]; score: number }) {
  const sum = rules.reduce((a, r) => a + (r.score || 0), 0);
  return (
    <div style={{ marginTop: 16 }}>
      <div style={sectionLabel}>
        Rules that matched ({rules.length}) — {sum} of anomaly score {score}
      </div>
      <div style={{ border: "1px solid var(--border2)", borderRadius: "var(--r2)", overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "var(--fs-sm)" }}>
          <thead>
            <tr style={{ background: "var(--bg3)", color: "var(--text3)", textAlign: "left" }}>
              <th style={{ padding: "6px 8px", fontWeight: 500 }}>Rule</th>
              <th style={{ padding: "6px 8px", fontWeight: 500 }}>Detected</th>
              <th style={{ padding: "6px 8px", fontWeight: 500 }}>Where</th>
              <th style={{ padding: "6px 8px", fontWeight: 500, textAlign: "right" }}>Score</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r, i) => (
              <tr key={`${r.id}-${i}`} style={{ borderTop: "1px solid var(--border2)" }} title={r.matched ? `matched: ${r.matched}` : undefined}>
                <td style={{ padding: "6px 8px", fontFamily: "var(--font-mono)", whiteSpace: "nowrap" }}>{r.id}</td>
                <td style={{ padding: "6px 8px", color: "var(--text2)" }}>{r.msg || "—"}</td>
                <td style={{ padding: "6px 8px", fontFamily: "var(--font-mono)", color: "var(--text2)", overflowWrap: "anywhere" }}>{r.target || "—"}</td>
                <td style={{ padding: "6px 8px", fontFamily: "var(--font-mono)", textAlign: "right" }}>{r.score}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/** The request's headers, redacted by the data plane before the row was
 *  written (sensitive names, session cookies, Referer/Origin query strings). */
function RequestHeaders({ headers }: { headers: Record<string, string> }) {
  const entries = Object.entries(headers);
  return (
    <details style={{ marginTop: 16 }}>
      <summary style={{ ...sectionLabel, cursor: "pointer", marginBottom: 0 }}>
        Request headers ({entries.length}) — redacted at the source
      </summary>
      <div style={{ marginTop: 8, padding: "8px 10px", borderRadius: "var(--r2)", background: "var(--bg3)", border: "1px solid var(--border2)", fontFamily: "var(--font-mono)", fontSize: "var(--fs-sm)" }}>
        {entries.map(([k, v]) => (
          <div key={k} style={{ overflowWrap: "anywhere", padding: "2px 0" }}>
            <span style={{ color: "var(--text3)" }}>{k}:</span> {v}
          </div>
        ))}
      </div>
    </details>
  );
}
