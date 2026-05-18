"use client";
import { useState, useEffect } from "react";
import { showToast } from "@/components/ui/Toast";
import { api, type Rule, type RuleTestResult } from "@/lib/api";

const PHASE_LABELS = ["conn","req_hdr","req_body","upstream","resp_hdr","resp_body","log"];

function SevBadge({ sev }: { sev: string }) {
  const cls = sev === "critical" ? "br blink" : sev === "high" ? "ba" : sev === "medium" ? "bcy" : "bgr";
  return <span className={`bdg ${cls}`}>{sev.slice(0, 3).toUpperCase()}</span>;
}

const BLANK_DSL = `rule my-custom-rule {
  id: 9000100
  phase: request_body
  target: ARGS | REQUEST_URI | REQUEST_BODY
  operator: rx('/(union|select|insert|update|delete|drop)/i')
  action: block
  severity: critical
  msg: "Custom SQL Injection Detection"
  anomaly_score: 10
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

  useEffect(() => {
    api.rules.list()
      .then(r => setRules(r.rules ?? []))
      .catch(() => showToast("Failed to load rules", "e", "⚠️"))
      .finally(() => setLoading(false));
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

  async function runTest() {
    const dsl = editorDSL.trim();
    if (!dsl) { showToast("No DSL to test", "w", "⚠️"); return; }
    setTestLoading(true); setTestResult(null);
    try {
      const res = await api.rules.test(dsl, testPayload, "POST", "/test");
      setTestResult(res);
    } catch { showToast("Test failed — check rule syntax", "e", "⚠️"); }
    finally { setTestLoading(false); }
  }

  return (
    <div className="sec">
      <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", gap:14 }}>
        <div>
          <div className="sec-title">📋 Rules Engine</div>
          <div className="sec-sub">OWASP CRS v4.7 · Custom SRL · Virtual Patches · {rules.length} loaded rules</div>
        </div>
        <div style={{ display:"flex", gap:8 }}>
          <button className="btn bc btn-sm" onClick={runTest} disabled={testLoading}>
            {testLoading ? "⏳ Testing…" : "🧪 Test Rule"}
          </button>
          <button className="btn bp btn-sm" onClick={() => {
            setEditorRule(null); setEditorDSL(BLANK_DSL);
            setEditorName(""); setEditorPhase(2); setEditorSev("high");
            setTestResult(null); setShowModal(true);
          }}>＋ New Rule</button>
        </div>
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 2fr", gap:16 }}>
        <div className="panel">
          <div className="ph">
            <div className="ptitle">📋 Rule Library</div>
            <div style={{ position:"relative" }}>
              <span style={{ position:"absolute", left:10, top:"50%", transform:"translateY(-50%)", color:"var(--text3)", fontSize:12, pointerEvents:"none" }}>🔍</span>
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
              <div style={{ padding:"24px", textAlign:"center", fontFamily:"'Share Tech Mono',monospace", fontSize:11, color:"var(--text3)" }}>Loading…</div>
            ) : (
              <table>
                <thead><tr><th>On</th><th>Name</th><th>Phase</th><th>Sev</th><th></th></tr></thead>
                <tbody>
                  {displayed.map(r => (
                    <tr key={r.id} onClick={() => openEditor(r)}
                      style={{ cursor:"pointer", background: editorRule?.id===r.id ? "rgba(0,200,240,0.06)" : undefined }}>
                      <td onClick={e => { e.stopPropagation(); toggleRule(r); }}>
                        <div className={`tog ${r.enabled?"on":""}`} />
                      </td>
                      <td><span style={{ color:"var(--cyan)", fontSize:10 }}>{r.name}</span></td>
                      <td className="td3">{PHASE_LABELS[r.phase]??`ph${r.phase}`}</td>
                      <td><SevBadge sev={r.severity} /></td>
                      <td>
                        {(r.source==="custom"||r.source==="ai_generated"||r.source==="virtual_patch") && (
                          <span style={{ cursor:"pointer", color:"var(--red-b)", fontSize:11 }}
                            onClick={e=>{ e.stopPropagation(); deleteRule(r); }}>🗑</span>
                        )}
                      </td>
                    </tr>
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
              {editorRule && <span style={{ fontSize:10, color:"var(--text3)", marginLeft:8 }}>— {editorRule.name}</span>}
            </div>
            <button className="btn bc btn-sm" onClick={runTest} disabled={testLoading}>
              {testLoading ? "⏳" : "▶ Test"}
            </button>
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
              <div style={{ padding:"16px 0", textAlign:"center", fontSize:11, fontFamily:"'Share Tech Mono',monospace", color:"var(--text3)" }}>
                ← Click a rule to inspect · or use &ldquo;＋ New Rule&rdquo;
              </div>
            )}

            {editorRule && (
              <div className="fg2">
                <label className="flbl2">SRL DSL</label>
                <textarea className="rule-ta" value={editorDSL} onChange={e => setEditorDSL(e.target.value)}
                  readOnly={editorRule.source==="crs"||editorRule.source==="community"} />
              </div>
            )}

            <div className="fg2">
              <label className="flbl2">Test Payload</label>
              <input className="fin2" value={testPayload} onChange={e => setTestPayload(e.target.value)}
                placeholder="Test payload, e.g.: 1' UNION SELECT * FROM users--" />
            </div>
            <button className="btn bc" onClick={runTest} disabled={testLoading}>
              {testLoading ? "⏳ Running…" : "▶ Run Test"}
            </button>

            {testResult && (
              <div className="code-block" style={{ whiteSpace:"pre-wrap" }}>
                <span style={{ color: testResult.verdict==="BLOCK" ? "var(--red-b)" : testResult.verdict==="ERROR" ? "var(--amber)" : "var(--green)" }}>
                  ● {testResult.verdict}
                </span>{" "}— {testResult.detail}{"\n"}
                Score: {testResult.anomaly_score} · Phases: {testResult.phases_run.join(", ")}
              </div>
            )}
          </div>
        </div>
      </div>

      {showModal && (
        <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.75)", zIndex:200, display:"flex", alignItems:"center", justifyContent:"center" }}>
          <div className="panel" style={{ width:560, maxHeight:"80vh", overflowY:"auto" }}>
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
                <button className="btn bp" onClick={createRule} disabled={saving}>
                  {saving ? "Saving…" : "💾 Create Rule"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
