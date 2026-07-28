"use client";
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import { api, type Rule, type RuleTestResult } from "@/lib/api";
import { staggerContainer, cardVariants, fadeUp, spring } from "@/lib/animations";

const PHASE_LABELS = ["conn","req_hdr","req_body","upstream","resp_hdr","resp_body","log"];

function SevBadge({ sev }: { sev: string }) {
  const cls = sev === "critical" ? "br blink" : sev === "high" ? "ba" : sev === "medium" ? "bcy" : "bgr";
  return <span className={`bdg ${cls}`}>{sev.slice(0, 3).toUpperCase()}</span>;
}

/** Whether the rule is actually RUNNING, as reported by the data plane.
 *
 * This column exists because the toggle beside it only ever showed what the
 * database stored. A rule whose DSL does not compile stays "enabled" forever
 * while protecting nothing, and this page was the one place an operator would
 * look and be misled. */
function EnforcementBadge({ r }: { r: Rule }) {
  const st = r.enforcement;
  if (!st) return <span className="td3" title="This control plane does not report enforcement">—</span>;

  const map: Record<string, { cls: string; label: string; tip: string }> = {
    enforced: {
      cls: "bgr", label: "LIVE",
      tip: `Compiled and enforcing on ${r.nodes_enforcing ?? "?"} node(s)`,
    },
    not_enforced: {
      cls: "br blink", label: "BROKEN",
      tip: r.enforcement_error || "The data plane could not compile this rule",
    },
    disabled:     { cls: "bgr", label: "OFF",     tip: "Switched off by an operator" },
    not_deployed: { cls: "bcy", label: "N/A",     tip: r.enforcement_note || "Not delivered to the data plane" },
    unknown:      { cls: "ba",  label: "UNKNOWN", tip: r.enforcement_note || "No node has reported recently" },
  };
  const m = map[st] ?? { cls: "ba", label: st.toUpperCase(), tip: st };
  return <span className={`bdg ${m.cls}`} title={m.tip}>{m.label}</span>;
}

// Valid SRL. The previous template was not: it used `rule <name> {` with a
// separate `id:` field, singular `target:`, and `operator: rx('...')`. None of
// that parses — the rule's NAME is its numeric id and the operator form is
// `rx /pattern/`. Every operator who clicked "New Rule" started from DSL that
// could never compile, which is why the template is now the same shape the
// engine's own rule files use.
const BLANK_DSL = `rule 9000100 {
  phase    : request_body
  targets  : ARGS|REQUEST_HEADERS|REQUEST_COOKIES
  operator : rx /(?i)(union\\s+select|drop\\s+table)/
  action   : block
  severity : critical
  message  : "Custom SQL injection detection"
}`;

export default function RulesPage() {
  const [rules, setRules]         = useState<Rule[]>([]);
  const [loading, setLoading]     = useState(true);
  const [activeTab, setActiveTab] = useState(0);
  const [search, setSearch]       = useState("");

  const [editorRule, setEditorRule]   = useState<Rule | null>(null);
  const [editorDSL, setEditorDSL]     = useState(BLANK_DSL);
  const [editorName, setEditorName]   = useState("");
  const [editorPhase, setEditorPhase] = useState(2);
  const [editorSev, setEditorSev]     = useState("high");
  const [testPayload, setTestPayload] = useState("1' UNION SELECT * FROM users--");
  const [testResult, setTestResult]   = useState<RuleTestResult | null>(null);
  const [testLoading, setTestLoading] = useState(false);
  const [saving, setSaving]           = useState(false);
  const [showModal, setShowModal]     = useState(false);

  const refresh = () =>
    api.rules.list()
      .then(r => setRules(r.rules ?? []))
      .catch(() => showToast("Failed to load rules", "e", "⚠️"));

  useEffect(() => { refresh().finally(() => setLoading(false)); }, []);

  // Enforcement comes from data-plane heartbeats, so it lags a change by a few
  // seconds. Poll while the page is open rather than leaving a stale "BROKEN"
  // badge on a rule the operator has just fixed.
  useEffect(() => {
    const t = setInterval(() => { void refresh(); }, 15000);
    return () => clearInterval(t);
  }, []);

  const tabs = [
    { label: "All",             data: rules },
    { label: "CRS",             data: rules.filter(r => r.source === "crs") },
    { label: "Custom",          data: rules.filter(r => r.source === "custom" || r.source === "ai_generated") },
    { label: "Virtual Patches", data: rules.filter(r => r.source === "virtual_patch") },
  ].map(t => ({ ...t, label: `${t.label} (${t.data.length})` }));

  const displayed = tabs[activeTab].data.filter(r => {
    const q = search.toLowerCase();
    return !q || r.name.toLowerCase().includes(q) || r.dsl.toLowerCase().includes(q);
  });

  async function toggleRule(r: Rule) {
    const next = !r.enabled;
    setRules(prev => prev.map(x => x.id === r.id ? { ...x, enabled: next } : x));
    try {
      await api.rules.toggle(r.id, next);
      showToast(`Rule "${r.name}" ${next ? "enabled" : "disabled"}`, "s", "📋");
    } catch {
      setRules(prev => prev.map(x => x.id === r.id ? { ...x, enabled: !next } : x));
      showToast("Failed to toggle rule", "e", "⚠️");
    }
  }

  async function deleteRule(r: Rule) {
    if (r.source === "crs" || r.source === "community") {
      showToast("CRS/community rules cannot be deleted", "w", "⚠️"); return;
    }
    if (!confirm(`Delete rule "${r.name}"?`)) return;
    try {
      await api.rules.delete(r.id);
      setRules(prev => prev.filter(x => x.id !== r.id));
      if (editorRule?.id === r.id) setEditorRule(null);
      showToast(`Rule "${r.name}" deleted`, "s", "🗑️");
    } catch { showToast("Failed to delete rule", "e", "⚠️"); }
  }

  function openEditor(r: Rule) {
    setEditorRule(r); setEditorDSL(r.dsl || BLANK_DSL);
    setEditorName(r.name); setEditorPhase(r.phase); setEditorSev(r.severity);
    setTestResult(null);
  }

  const editorReadOnly =
    editorRule?.source === "crs" || editorRule?.source === "community";

  async function createRule() {
    if (!editorName.trim()) { showToast("Rule name is required", "w", "⚠️"); return; }
    setSaving(true);
    try {
      const res = await api.rules.create({
        name: editorName, source: "custom",
        phase: editorPhase, severity: editorSev as Rule["severity"],
        dsl: editorDSL, enabled: true, tags: [],
      });
      setRules(prev => [res.rule, ...prev]);
      setEditorRule(res.rule); setShowModal(false);
      showToast(`Rule "${res.rule.name}" created`, "s", "📋");
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : "Create failed", "e", "⚠️");
    } finally { setSaving(false); }
  }

  /** Persist an edited rule. The textarea has always been editable and there was
   *  no way to save it, so an operator's only route to fixing a typo was delete
   *  and recreate — which changes the rule id and orphans its audit history.
   *
   *  A rejected save leaves the EXISTING rule in place: the API validates the new
   *  DSL against the real engine before replacing anything, so a 400 here means
   *  nothing changed rather than a working rule having been overwritten. */
  async function saveRule() {
    if (!editorRule) return;
    if (editorRule.source === "crs" || editorRule.source === "community") {
      showToast("Shipped CRS/community rules are read-only", "w", "⚠️"); return;
    }
    setSaving(true);
    try {
      const res = await api.rules.update(editorRule.id, {
        dsl: editorDSL, severity: editorSev, phase: editorPhase,
      });
      setRules(prev => prev.map(x => x.id === res.rule.id ? res.rule : x));
      setEditorRule(res.rule);
      showToast(res.warning ?? `Rule "${res.rule.name}" saved`, res.warning ? "w" : "s", "💾");
      // Enforcement is reported by the data plane after it re-fetches config, so
      // the badge is stale for a few seconds; pull it once it has had time.
      setTimeout(() => { void refresh(); }, 12000);
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : "Save failed — the rule was not changed", "e", "⚠️");
    } finally { setSaving(false); }
  }

  async function runTest() {
    const dsl = editorDSL.trim();
    if (!dsl) { showToast("No DSL to test", "w", "⚠️"); return; }
    setTestLoading(true); setTestResult(null);
    try {
      const res = await api.rules.test(dsl, testPayload, "POST", "/test");
      setTestResult(res);
    } catch (err: unknown) {
      // An invalid rule comes back 200 with valid:false, so reaching here means
      // the request itself failed — most often the validator is unavailable on
      // this node. Blaming the operator's syntax would misattribute it.
      showToast(err instanceof Error ? err.message : "Could not run the test", "e", "⚠️");
    }
    finally { setTestLoading(false); }
  }

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <motion.div variants={fadeUp} style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", gap:14 }}>
        <div>
          <div className="sec-title">📋 Rules Engine</div>
          <div className="sec-sub">OWASP CRS v4.7 · Custom SRL · Virtual Patches · {rules.length} loaded rules</div>
        </div>
        <div style={{ display:"flex", gap:8 }}>
          <motion.button className="btn bc btn-sm" onClick={runTest} disabled={testLoading} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
            {testLoading ? "⏳ Testing…" : "🧪 Test Rule"}
          </motion.button>
          <motion.button className="btn bp btn-sm" whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }} onClick={() => {
            setEditorRule(null); setEditorDSL(BLANK_DSL);
            setEditorName(""); setEditorPhase(2); setEditorSev("high");
            setTestResult(null); setShowModal(true);
          }}>＋ New Rule</motion.button>
        </div>
      </motion.div>

      <motion.div variants={fadeUp} style={{ display:"grid", gridTemplateColumns:"1fr 2fr", gap:16 }}>
        <div className="panel">
          <div className="ph">
            <div className="ptitle">📋 Rule Library</div>
            <div style={{ position:"relative" }}>
              <span style={{ position:"absolute", left:10, top:"50%", transform:"translateY(-50%)", color:"var(--text3)", fontSize: 14, pointerEvents:"none" }}>🔍</span>
              <input className="fi2" type="text" placeholder="Search…" style={{ width:150 }}
                value={search} onChange={e => setSearch(e.target.value)} />
            </div>
          </div>
          <div className="tabs">
            {tabs.map((t, i) => (
              <div key={i} className={`tab ${activeTab===i?"active":""}`}
                onClick={() => { setActiveTab(i); setSearch(""); }}>{t.label}</div>
            ))}
          </div>
          <div className="tw" style={{ maxHeight:480, overflowY:"auto" }}>
            {loading ? (
              <div style={{ padding:"24px", textAlign:"center", fontFamily:"var(--font-mono)", fontSize: 13, color:"var(--text3)" }}>Loading…</div>
            ) : (
              <table>
                <thead><tr><th>On</th><th>Name</th><th>Running</th><th>Phase</th><th>Sev</th><th></th></tr></thead>
                <tbody>
                  {displayed.map(r => (
                    <motion.tr key={r.id} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.2 }}
                      onClick={() => openEditor(r)}
                      style={{ cursor:"pointer", background: editorRule?.id===r.id ? "rgba(0,200,240,0.06)" : undefined }}>
                      <td onClick={e => { e.stopPropagation(); toggleRule(r); }}>
                        <div className={`tog ${r.enabled?"on":""}`} />
                      </td>
                      <td>
                        <span style={{ color:"var(--cyan)", fontSize: 14 }}>{r.name}</span>
                        {r.site_id && (
                          <span className="td3" style={{ fontSize: 11, marginLeft: 6 }}
                            title="Scoped to a single site; deployment-wide rules show no tag">site</span>
                        )}
                      </td>
                      <td><EnforcementBadge r={r} /></td>
                      <td className="td3">{PHASE_LABELS[r.phase]??`ph${r.phase}`}</td>
                      <td><SevBadge sev={r.severity} /></td>
                      <td>
                        {(r.source==="custom"||r.source==="ai_generated"||r.source==="virtual_patch") && (
                          <span style={{ cursor:"pointer", color:"var(--red-b)", fontSize: 13 }}
                            onClick={e=>{ e.stopPropagation(); deleteRule(r); }}>🗑</span>
                        )}
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div className="panel" style={{ display:"flex", flexDirection:"column" }}>
          <div className="ph">
            <div className="ptitle">
              ✏️ Rule Editor
              {editorRule && <span style={{ fontSize: 14, color:"var(--text3)", marginLeft:8 }}>— {editorRule.name}</span>}
            </div>
            <motion.button className="btn bc btn-sm" onClick={runTest} disabled={testLoading} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
              {testLoading ? "⏳" : "▶ Test"}
            </motion.button>
          </div>
          <div className="pb" style={{ flex:1, display:"flex", flexDirection:"column", gap:12 }}>
            {editorRule ? (
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
                <div className="fg2"><label className="flbl2">Name</label>
                  <input className="fin2" value={editorRule.name} readOnly style={{ opacity:0.6 }} /></div>
                <div className="fg2"><label className="flbl2">Phase</label>
                  <input className="fin2" value={PHASE_LABELS[editorRule.phase]??`phase ${editorRule.phase}`} readOnly style={{ opacity:0.6 }} /></div>
              </div>
            ) : (
              <div style={{ padding:"16px 0", textAlign:"center", fontSize: 13, fontFamily:"var(--font-mono)", color:"var(--text3)" }}>
                ← Click a rule to inspect · or use &ldquo;＋ New Rule&rdquo;
              </div>
            )}

            {editorRule && editorRule.enforcement === "not_enforced" && (
              <div className="code-block" style={{ whiteSpace:"pre-wrap", borderLeft:"3px solid var(--red-b)" }}>
                <span style={{ color:"var(--red-b)" }}>● NOT ENFORCED</span> — this rule is
                stored and enabled but the data plane could not compile it, so it is
                protecting nothing.{"\n"}
                {editorRule.enforcement_error || "no reason reported"}
              </div>
            )}

            {editorRule && !editorReadOnly && (
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
                <div className="fg2"><label className="flbl2">Severity</label>
                  <select className="fin2 fsel2" value={editorSev} onChange={e=>setEditorSev(e.target.value)}>
                    <option value="critical">Critical</option><option value="high">High</option>
                    <option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option>
                  </select></div>
                <div className="fg2"><label className="flbl2">Phase</label>
                  <select className="fin2 fsel2" value={editorPhase} onChange={e=>setEditorPhase(Number(e.target.value))}>
                    {PHASE_LABELS.map((l,i) => <option key={i} value={i}>{i} — {l}</option>)}
                  </select></div>
              </div>
            )}

            {editorRule && (
              <div className="fg2">
                <label className="flbl2">
                  SRL DSL {editorReadOnly && <span className="td3">(shipped rule — read-only)</span>}
                </label>
                <textarea className="rule-ta" value={editorDSL} onChange={e => setEditorDSL(e.target.value)}
                  readOnly={editorReadOnly} />
              </div>
            )}

            {editorRule && !editorReadOnly && (
              <motion.button className="btn bp" onClick={saveRule} disabled={saving}
                whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                {saving ? "Saving…" : "💾 Save Changes"}
              </motion.button>
            )}

            <div className="fg2">
              <label className="flbl2">Test Payload</label>
              <input className="fin2" value={testPayload} onChange={e => setTestPayload(e.target.value)}
                placeholder="Test payload, e.g.: 1' UNION SELECT * FROM users--" />
            </div>
            <motion.button className="btn bc" onClick={runTest} disabled={testLoading} whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
              {testLoading ? "⏳ Running…" : "▶ Run Test"}
            </motion.button>

            {testResult && (
              <motion.div className="code-block" style={{ whiteSpace:"pre-wrap" }} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
                <span style={{ color:
                  testResult.valid === false ? "var(--red-b)"
                  : testResult.verdict === "BLOCK" ? "var(--red-b)"
                  : testResult.verdict === "ERROR" ? "var(--amber)"
                  : "var(--green)" }}>
                  ● {testResult.valid === false ? "DOES NOT COMPILE" : testResult.verdict}
                </span>{" "}— {testResult.detail}{"\n"}
                {testResult.valid !== false && (
                  <>
                    Score: {testResult.anomaly_score}
                    {testResult.decision ? ` · Decision: ${testResult.decision}` : ""}
                    {testResult.matched_rule_ids?.length
                      ? ` · Matched: ${testResult.matched_rule_ids.join(", ")}`
                      : ""}
                    {"\n"}
                    {testResult.rules?.length
                      ? `Compiled: ${testResult.rules.map(x => `${x.id} (${x.phase}, ${x.action})`).join("; ")}`
                      : ""}
                  </>
                )}
              </motion.div>
            )}
          </div>
        </div>
      </motion.div>

      {showModal && (
        <motion.div
          style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.75)", zIndex:200, display:"flex", alignItems:"center", justifyContent:"center" }}
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        >
          <motion.div className="panel" style={{ width:560, maxHeight:"80vh", overflowY:"auto" }} initial={{ scale: 0.94, y: 14 }} animate={{ scale: 1, y: 0 }} transition={spring}>
            <div className="ph">
              <div className="ptitle">＋ New Custom Rule</div>
              <button className="btn bg-btn btn-sm" onClick={() => setShowModal(false)}>✕</button>
            </div>
            <div className="pb" style={{ display:"flex", flexDirection:"column", gap:12 }}>
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
                <div className="fg2"><label className="flbl2">Rule Name *</label>
                  <input className="fin2" placeholder="block-sqli-custom" value={editorName} onChange={e=>setEditorName(e.target.value)} /></div>
                <div className="fg2"><label className="flbl2">Severity</label>
                  <select className="fin2 fsel2" value={editorSev} onChange={e=>setEditorSev(e.target.value)}>
                    <option value="critical">Critical</option><option value="high">High</option>
                    <option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option>
                  </select></div>
                <div className="fg2"><label className="flbl2">Phase</label>
                  <select className="fin2 fsel2" value={editorPhase} onChange={e=>setEditorPhase(Number(e.target.value))}>
                    {PHASE_LABELS.map((l,i) => <option key={i} value={i}>{i} — {l}</option>)}
                  </select></div>
              </div>
              <div className="fg2"><label className="flbl2">SRL DSL</label>
                <textarea className="rule-ta" value={editorDSL} onChange={e=>setEditorDSL(e.target.value)} style={{ minHeight:160 }} /></div>
              <div style={{ display:"flex", gap:8, justifyContent:"flex-end" }}>
                <button className="btn bg-btn" onClick={() => setShowModal(false)}>Cancel</button>
                <motion.button className="btn bp" onClick={createRule} disabled={saving} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
                  {saving ? "Saving…" : "💾 Create Rule"}
                </motion.button>
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </motion.div>
  );
}