"use client";
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import FirstRunNote from "@/components/ui/FirstRunNote";
import { api, type Rule, type RuleTestResult, type CompiledRule, type RuleInventory, type SiteRuleInventory } from "@/lib/api";
import { staggerContainer, cardVariants, fadeUp, spring } from "@/lib/animations";
import Icon from "@/components/ui/Icon";

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

/** Right-hand panel for the Compiled tab: the enforced set's totals and gaps,
 *  and the selected compiled rule. Read-only by design — these rules come from
 *  the CRS files and the site's policy, not from the authored store. */
function CompiledDetail({ inv, site, rule }: { inv: RuleInventory | null; site?: SiteRuleInventory; rule: CompiledRule | null }) {
  if (!inv) return <div className="td3" style={{ padding:"16px 0", textAlign:"center", fontSize:13, fontFamily:"var(--font-sans)" }}>Loading the enforced rule set…</div>;
  if (!inv.dataplane_reachable) {
    return (
      <div className="code-block" style={{ whiteSpace:"pre-wrap", borderLeft:"3px solid var(--red-b)" }}>
        <span style={{ color:"var(--red-b)" }}>● DATA PLANE UNREACHABLE</span> — the control plane could not
        fetch the compiled inventory, so nothing on this tab is known.{"\n"}{inv.error ?? ""}
      </div>
    );
  }
  const t = inv.totals;
  const gaps = (site?.dropped.length ?? 0) + (site?.disabled.length ?? 0);
  const stat = (label: string, value: string, color?: string) => (
    <div style={{ minWidth:110 }}>
      <div className="td3" style={{ fontSize:11 }}>{label}</div>
      <div style={{ fontFamily:"var(--font-sans)", fontSize:18, fontVariantNumeric:"tabular-nums", color }}>{value}</div>
    </div>
  );
  return (
    <>
      <div style={{ display:"flex", gap:18, flexWrap:"wrap" }}>
        {stat("compiled", t.compiled.toLocaleString())}
        {stat("enforcing", t.enforced.toLocaleString(), "var(--green)")}
        {stat("failed to compile", String(t.dropped), t.dropped > 0 ? "var(--red-b)" : undefined)}
        {stat("inert", String(t.disabled), t.disabled > 0 ? "var(--amber)" : undefined)}
        {stat("hits · 24h", inv.clickhouse ? (t.hits_24h ?? 0).toLocaleString() : "no event store")}
      </div>
      <div className="td3" style={{ fontSize:12.5, lineHeight:1.5 }}>
        This is what the data plane is enforcing right now{inv.version ? ` (data plane ${inv.version})` : ""}:
        the OWASP CRS files, the placement and coverage signatures, and every authored rule that
        compiled. The Authored tabs list what this control plane stores; the two are not the same thing.
      </div>

      {gaps > 0 && site && (
        <div className="code-block" style={{ whiteSpace:"pre-wrap", borderLeft:"3px solid var(--amber)" }}>
          <span style={{ color:"var(--amber)" }}>● {gaps} RULE{gaps === 1 ? "" : "S"} NOT ENFORCED on {site.site}</span>{"\n"}
          {site.dropped.map(d => `${d.id}  failed to compile — ${d.reason}`).join("\n")}
          {site.dropped.length > 0 && site.disabled.length > 0 ? "\n" : ""}
          {site.disabled.length > 0 ? `inert (unsupported operator): ${site.disabled.join(", ")}` : ""}
        </div>
      )}

      {rule ? (
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
          <div className="fg2"><label className="flbl2">Rule id</label>
            <input className="fin2" value={String(rule.id)} readOnly style={{ opacity:0.7 }} /></div>
          <div className="fg2"><label className="flbl2">Phase</label>
            <input className="fin2" value={PHASE_LABELS[rule.phase] ?? `phase ${rule.phase}`} readOnly style={{ opacity:0.7 }} /></div>
          <div className="fg2" style={{ gridColumn:"1 / -1" }}><label className="flbl2">Message</label>
            <input className="fin2" value={rule.message || "—"} readOnly style={{ opacity:0.7 }} /></div>
          <div className="fg2"><label className="flbl2">Severity · action · score</label>
            <input className="fin2" value={`${rule.severity} · ${rule.action} · ${rule.score_delta >= 0 ? "+" : ""}${rule.score_delta}`} readOnly style={{ opacity:0.7 }} /></div>
          <div className="fg2"><label className="flbl2">Paranoia level · category</label>
            <input className="fin2" value={`${rule.paranoia_level ?? "—"} · ${rule.category ?? "—"}`} readOnly style={{ opacity:0.7 }} /></div>
          <div className="fg2"><label className="flbl2">Hits · blocks (24h)</label>
            <input className="fin2" value={inv.clickhouse ? `${(rule.hits_24h ?? 0).toLocaleString()} · ${(rule.blocks_24h ?? 0).toLocaleString()}` : "no event store configured"} readOnly style={{ opacity:0.7 }} /></div>
          <div className="fg2"><label className="flbl2">Enforcement</label>
            <input className="fin2" value={rule.inert ? "INERT — loaded, operator unsupported, can never match" : "LIVE — compiled and evaluated on every request"} readOnly style={{ opacity:0.7, color: rule.inert ? "var(--amber)" : "var(--green)" }} /></div>
          <div className="fg2" style={{ gridColumn:"1 / -1" }}><label className="flbl2">Tags</label>
            <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
              {rule.tags.length ? rule.tags.map(tg => <span key={tg} className="bdg bcy" style={{ textTransform:"none" }}>{tg}</span>) : <span className="td3">—</span>}
            </div></div>
        </div>
      ) : (
        <div className="td3" style={{ padding:"12px 0", textAlign:"center", fontSize:13, fontFamily:"var(--font-sans)" }}>
          ← Click a compiled rule to inspect it
        </div>
      )}
    </>
  );
}

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
  // Which site a rule applies to. "" = every site in the deployment, which is
  // what every console-authored rule has been until now: `rules.site_id` has
  // existed since migration 0018, attachInlineRules honours it, and this page
  // even shows a "site" tag for a scoped rule — but nothing here could SET it,
  // so the scoping was reachable only through the API. A capability with no
  // input is the same as an absent one.
  const [editorSite, setEditorSite]   = useState("");
  const [siteList, setSiteList]       = useState<Array<{ id: string; name: string }>>([]);
  const [testPayload, setTestPayload] = useState("1' UNION SELECT * FROM users--");
  const [testResult, setTestResult]   = useState<RuleTestResult | null>(null);
  const [testLoading, setTestLoading] = useState(false);
  const [saving, setSaving]           = useState(false);
  const [showModal, setShowModal]     = useState(false);

  // The compiled inventory — what the data plane ENFORCES. The authored list
  // above is what this control plane STORES. Showing only the second under the
  // heading "loaded rules" made a 347-rule engine read as a six-rule WAF.
  const [inv, setInv]                 = useState<RuleInventory | null>(null);
  const [invSite, setInvSite]         = useState<string>("");
  const [selCompiled, setSelCompiled] = useState<CompiledRule | null>(null);
  const [plFilter, setPlFilter]       = useState<number>(0);

  const refresh = () => Promise.all([
    api.rules.list()
      .then(r => setRules(r.rules ?? []))
      .catch(() => showToast("Failed to load rules", "e")),
    api.rules.inventory()
      .then(setInv)
      .catch(() => setInv({ dataplane_reachable: false, error: "control plane did not answer", sites: [],
                            totals: { compiled: 0, enforced: 0, dropped: 0, disabled: 0 } })),
  ]);

  useEffect(() => { refresh().finally(() => setLoading(false)); }, []);

  // Enforcement comes from data-plane heartbeats, so it lags a change by a few
  // seconds. Poll while the page is open rather than leaving a stale "BROKEN"
  // badge on a rule the operator has just fixed.
  useEffect(() => {
    const t = setInterval(() => { void refresh(); }, 15000);
    return () => clearInterval(t);
  }, []);

  const authoredTabs = [
    { label: "Authored",        data: rules },
    { label: "CRS",             data: rules.filter(r => r.source === "crs") },
    { label: "Custom",          data: rules.filter(r => r.source === "custom" || r.source === "ai_generated") },
    { label: "Virtual Patches", data: rules.filter(r => r.source === "virtual_patch") },
  ].map(t => ({ ...t, label: `${t.label} (${t.data.length})` }));
  const compiledLabel = inv?.dataplane_reachable ? `Compiled (${inv.totals.enforced.toLocaleString()})` : "Compiled";
  const tabs = [{ label: compiledLabel, data: [] as Rule[] }, ...authoredTabs];
  const isCompiledTab = activeTab === 0;

  const displayed = isCompiledTab ? [] : tabs[activeTab].data.filter(r => {
    const q = search.toLowerCase();
    return !q || r.name.toLowerCase().includes(q) || r.dsl.toLowerCase().includes(q);
  });

  const [showControlFlow, setShowControlFlow] = useState(false);
  const invSites = inv?.sites ?? [];
  const curSite  = invSites.find(s => s.site === invSite) ?? invSites[0];
  // CRS paranoia GATES, not detection rules. Each is
  //   SecRule TX:DETECTION_PARANOIA_LEVEL "@lt N" ... pass,nolog,skipAfter:END-...
  // — control flow that decides whether the block below it runs at this paranoia
  // level. They never match traffic, never score and never log, so they have no
  // message, no category and no score delta, and the table rendered 107 of them
  // as blank "— —" rows among 243 real rules. They are hidden by default and
  // counted, rather than dropped: the totals above say 350 enforced and a table
  // that silently showed 243 would be its own contradiction.
  const isControlFlow = (r: { message?: string; category?: string | null; score_delta?: number }) =>
    !r.message && !r.category && (r.score_delta ?? 0) === 0;
  const allSiteRules = curSite?.rules ?? [];
  const controlFlowCount = allSiteRules.filter(isControlFlow).length;
  const compiledRows = allSiteRules.filter(r => {
    if (!showControlFlow && isControlFlow(r)) return false;
    if (plFilter && r.paranoia_level !== plFilter) return false;
    const q = search.toLowerCase();
    return !q || String(r.id).includes(q) || r.message.toLowerCase().includes(q)
      || (r.category ?? "").includes(q) || r.tags.some(t => t.toLowerCase().includes(q));
  });

  async function toggleRule(r: Rule) {
    const next = !r.enabled;
    setRules(prev => prev.map(x => x.id === r.id ? { ...x, enabled: next } : x));
    try {
      await api.rules.toggle(r.id, next);
      showToast(`Rule "${r.name}" ${next ? "enabled" : "disabled"}`, "s");
    } catch {
      setRules(prev => prev.map(x => x.id === r.id ? { ...x, enabled: !next } : x));
      showToast("Failed to toggle rule", "e");
    }
  }

  async function deleteRule(r: Rule) {
    if (r.source === "crs" || r.source === "community") {
      showToast("CRS/community rules cannot be deleted", "w"); return;
    }
    if (!confirm(`Delete rule "${r.name}"?`)) return;
    try {
      await api.rules.delete(r.id);
      setRules(prev => prev.filter(x => x.id !== r.id));
      if (editorRule?.id === r.id) setEditorRule(null);
      showToast(`Rule "${r.name}" deleted`, "s");
    } catch { showToast("Failed to delete rule", "e"); }
  }

  function openEditor(r: Rule) {
    setEditorRule(r); setEditorDSL(r.dsl || BLANK_DSL);
    setEditorName(r.name); setEditorPhase(r.phase); setEditorSev(r.severity);
    setEditorSite(r.site_id ?? "");
    setTestResult(null);
    void loadSitesForScoping();
  }

  /** The scope control. Rendered in both the edit panel and the create modal —
   *  a rule authored deployment-wide and then narrowed is the common path, and
   *  offering it in only one of the two would leave the other lying by omission. */
  function ScopeSelect({ disabled }: { disabled?: boolean }) {
    return (
      <div className="fg2">
        <label className="flbl2">Applies to</label>
        <select className="fin2 fsel2" value={editorSite} disabled={disabled}
          onChange={e => setEditorSite(e.target.value)}>
          <option value="">Every site (deployment-wide)</option>
          {siteList.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
        <div className="td3" style={{ fontSize: 11, marginTop: 3, lineHeight: 1.4 }}>
          {editorSite
            ? "Compiled into this site's engine only. Other sites never see it."
            : "Compiled into every site's engine, including sites created later."}
        </div>
      </div>
    );
  }

  const editorReadOnly =
    editorRule?.source === "crs" || editorRule?.source === "community";

  /** Open the create modal from a clean slate: a new rule defaults to
   *  deployment-wide, and the site list has to be there before the selector is
   *  rendered or it would offer only that one option. */
  function openCreate() {
    setEditorSite("");
    void loadSitesForScoping();
    setShowModal(true);
  }

  async function createRule() {
    if (!editorName.trim()) { showToast("Rule name is required", "w"); return; }
    setSaving(true);
    try {
      const res = await api.rules.create({
        name: editorName, source: "custom",
        phase: editorPhase, severity: editorSev as Rule["severity"],
        dsl: editorDSL, enabled: true, tags: [],
        // Omitted when empty: the API treats an absent site_id as
        // deployment-wide, which is the safe default for a new rule.
        ...(editorSite ? { site_id: editorSite } : {}),
      });
      setRules(prev => [res.rule, ...prev]);
      setEditorRule(res.rule); setShowModal(false);
      showToast(`Rule "${res.rule.name}" created`, "s");
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : "Create failed", "e");
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
      showToast("Shipped CRS/community rules are read-only", "w"); return;
    }
    setSaving(true);
    try {
      const res = await api.rules.update(editorRule.id, {
        dsl: editorDSL, severity: editorSev, phase: editorPhase,
        // An omitted field is left alone, so widening a rule back to every site
        // needs the explicit clear flag rather than an empty string.
        ...(editorSite ? { site_id: editorSite } : { clear_site_id: true }),
      });
      setRules(prev => prev.map(x => x.id === res.rule.id ? res.rule : x));
      setEditorRule(res.rule);
      showToast(res.warning ?? `Rule "${res.rule.name}" saved`, res.warning ? "w" : "s");
      // Enforcement is reported by the data plane after it re-fetches config, so
      // the badge is stale for a few seconds; pull it once it has had time.
      setTimeout(() => { void refresh(); }, 12000);
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : "Save failed — the rule was not changed", "e");
    } finally { setSaving(false); }
  }

  async function loadSitesForScoping() {
    try {
      const r = await api.sites.list();
      setSiteList((r.sites ?? []).map(x => ({ id: x.id, name: x.name })));
    } catch {
      // A rule can still be authored deployment-wide without this list; the
      // selector just shows only that option.
      setSiteList([]);
    }
  }

  async function runTest() {
    const dsl = editorDSL.trim();
    if (!dsl) { showToast("No DSL to test", "w"); return; }
    setTestLoading(true); setTestResult(null);
    try {
      const res = await api.rules.test(dsl, testPayload, "POST", "/test");
      setTestResult(res);
    } catch (err: unknown) {
      // An invalid rule comes back 200 with valid:false, so reaching here means
      // the request itself failed — most often the validator is unavailable on
      // this node. Blaming the operator's syntax would misattribute it.
      showToast(err instanceof Error ? err.message : "Could not run the test", "e");
    }
    finally { setTestLoading(false); }
  }

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <FirstRunNote id="rules" title="This page shows two different rule sets">
        The OWASP Core Rule Set is compiled into the data plane and enforced as a whole — the
        &ldquo;enforcing&rdquo; figure is what the engine actually runs, and anything that failed to
        compile is counted separately rather than silently skipped. Rules you author here are the
        second set, and each one can apply to a single site or to every site. A site in
        <strong> learning</strong> mode scores matches and does not block them, so a rule can be
        matching constantly and changing nothing.
      </FirstRunNote>
      <motion.div variants={fadeUp} style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", gap:14 }}>
        <div>
          <div className="sec-title">Rules Engine</div>
          <div className="sec-sub">
            {inv == null ? "reading the enforced rule set…"
              : !inv.dataplane_reachable ? "data plane unreachable — enforced rule set unknown"
              : `${inv.totals.enforced.toLocaleString()} rules enforcing on the data plane`
                + (inv.totals.dropped ? ` · ${inv.totals.dropped} failed to compile` : "")
                + (inv.totals.disabled ? ` · ${inv.totals.disabled} inert` : "")}
            {" · "}{rules.length} authored in this control plane
          </div>
        </div>
        <div style={{ display:"flex", gap:8 }}>
          <motion.button className="btn bc btn-sm" onClick={runTest} disabled={testLoading} whileTap={{ scale: 0.97 }}>
            {testLoading ? "⏳ Testing…" : "Test Rule"}
          </motion.button>
          <motion.button className="btn bp btn-sm" whileTap={{ scale: 0.97 }} onClick={() => {
            setEditorRule(null); setEditorDSL(BLANK_DSL);
            setEditorName(""); setEditorPhase(2); setEditorSev("high");
            setTestResult(null); openCreate();
          }}>＋ New Rule</motion.button>
        </div>
      </motion.div>

      <motion.div variants={fadeUp} style={{ display:"grid", gridTemplateColumns:"1fr 2fr", gap:16 }}>
        <div className="panel">
          <div className="ph">
            <div className="ptitle">Rule Library</div>
            <div style={{ position:"relative" }}>
              <span style={{ position:"absolute", left:10, top:"50%", transform:"translateY(-50%)", color:"var(--text3)", fontSize: 14, pointerEvents:"none" }}><Icon name="search" size={14} /></span>
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
          {isCompiledTab && inv?.dataplane_reachable && (
            <div style={{ display:"flex", gap:8, padding:"8px 12px 0", alignItems:"center", flexWrap:"wrap" }}>
              {invSites.length > 1 && (
                <select className="fin2 fsel2" value={curSite?.site ?? ""} onChange={e => { setInvSite(e.target.value); setSelCompiled(null); }} style={{ width:180 }}>
                  {invSites.map(si => <option key={si.site} value={si.site}>{si.site}</option>)}
                </select>
              )}
              <select className="fin2 fsel2" value={plFilter} onChange={e => setPlFilter(Number(e.target.value))} style={{ width:120 }}>
                <option value={0}>All PL</option><option value={1}>PL1</option><option value={2}>PL2</option>
                <option value={3}>PL3</option><option value={4}>PL4</option>
              </select>
              <span className="td3" style={{ fontSize:12, fontFamily:"var(--font-sans)" }}>{compiledRows.length} shown</span>
              {controlFlowCount > 0 && (
                <button className="btn bg-btn btn-xs" onClick={() => setShowControlFlow(v => !v)}
                  title="CRS paranoia gates: SecRule TX:DETECTION_PARANOIA_LEVEL @lt N … skipAfter. They decide which block runs at the configured paranoia level, and never match traffic.">
                  {showControlFlow ? `hide ${controlFlowCount} control-flow` : `show ${controlFlowCount} control-flow`}
                </button>
              )}
            </div>
          )}
          <div className="tw" style={{ maxHeight:480, overflowY:"auto" }}>
            {isCompiledTab ? (
              !inv ? (
                <div style={{ padding:"24px", textAlign:"center", fontFamily:"var(--font-sans)", fontSize: 13, color:"var(--text3)" }}>Loading…</div>
              ) : !inv.dataplane_reachable ? (
                <div style={{ padding:"24px", textAlign:"center", fontFamily:"var(--font-sans)", fontSize: 13, color:"var(--red-b)" }}>data plane unreachable</div>
              ) : (
                <table>
                  <thead><tr><th>Rule</th><th>Message</th><th>PL</th><th>Sev</th><th title="events attributed to this rule in the last 24 hours (ClickHouse)">Hits 24h</th></tr></thead>
                  <tbody>
                    {compiledRows.map(r => (
                      <tr key={r.id} onClick={() => setSelCompiled(r)}
                        style={{ cursor:"pointer", opacity: r.inert ? 0.55 : 1,
                                 background: selCompiled?.id === r.id ? "var(--accent-tint)" : undefined }}>
                        <td>
                          <span style={{ color:"var(--cyan)", fontSize: 14, fontFamily:"var(--font-mono)" }}>{r.id}</span>
                          {r.inert && <span className="bdg ba" style={{ marginLeft:6 }} title="Loaded, but its operator is unsupported by the engine — it can never match">INERT</span>}
                        </td>
                        <td className="td3" title={isControlFlow(r) ? "Paranoia gate — decides whether the following block runs at this paranoia level. Never matches traffic." : r.message}
                            style={{ maxWidth:240, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap",
                                     fontStyle: isControlFlow(r) ? "italic" : undefined }}>
                          {r.message || r.category || (isControlFlow(r) ? "paranoia gate · control flow" : "—")}
                        </td>
                        <td className="td3">{r.paranoia_level ?? "—"}</td>
                        <td><SevBadge sev={r.severity === "notice" ? "info" : r.severity} /></td>
                        <td className="td3" style={{ fontVariantNumeric:"tabular-nums", fontFamily:"var(--font-sans)" }}>{inv.clickhouse ? (r.hits_24h ?? 0).toLocaleString() : "—"}</td>
                      </tr>
                    ))}
                    {compiledRows.length === 0 && (
                      <tr><td colSpan={5} className="td3" style={{ textAlign:"center", padding:18 }}>no compiled rules match</td></tr>
                    )}
                  </tbody>
                </table>
              )
            ) : loading ? (
              <div style={{ padding:"24px", textAlign:"center", fontFamily:"var(--font-sans)", fontSize: 13, color:"var(--text3)" }}>Loading…</div>
            ) : (
              <table>
                <thead><tr><th>On</th><th>Name</th><th>Running</th><th>Phase</th><th>Sev</th><th></th></tr></thead>
                <tbody>
                  {displayed.map(r => (
                    <motion.tr key={r.id} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.2 }}
                      onClick={() => openEditor(r)}
                      style={{ cursor:"pointer", background: editorRule?.id===r.id ? "var(--accent-tint)" : undefined }}>
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
                            onClick={e=>{ e.stopPropagation(); deleteRule(r); }}><Icon name="trash" size={14} title="Delete rule" /></span>
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
              {isCompiledTab ? "Enforced rule set" : "Rule Editor"}
              {!isCompiledTab && editorRule && <span style={{ fontSize: 14, color:"var(--text3)", marginLeft:8 }}>— {editorRule.name}</span>}
            </div>
            <motion.button className="btn bc btn-sm" onClick={runTest} disabled={testLoading} whileTap={{ scale: 0.97 }}>
              {testLoading ? "⏳" : "▶ Test"}
            </motion.button>
          </div>
          <div className="pb" style={{ flex:1, display:"flex", flexDirection:"column", gap:12 }}>
            {isCompiledTab ? (
              <CompiledDetail inv={inv} site={curSite} rule={selCompiled} />
            ) : (<>
            {editorRule ? (
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
                <div className="fg2"><label className="flbl2">Name</label>
                  <input className="fin2" value={editorRule.name} readOnly style={{ opacity:0.6 }} /></div>
                <div className="fg2"><label className="flbl2">Phase</label>
                  <input className="fin2" value={PHASE_LABELS[editorRule.phase]??`phase ${editorRule.phase}`} readOnly style={{ opacity:0.6 }} /></div>
              </div>
            ) : (
              <div style={{ padding:"16px 0", textAlign:"center", fontSize: 13, fontFamily:"var(--font-sans)", color:"var(--text3)" }}>
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
                <ScopeSelect />
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
              <motion.button className="btn bp" onClick={saveRule} disabled={saving} whileTap={{ scale: 0.97 }}>
                {saving ? "Saving…" : "Save Changes"}
              </motion.button>
            )}

            <div className="fg2">
              <label className="flbl2">Test Payload</label>
              <input className="fin2" value={testPayload} onChange={e => setTestPayload(e.target.value)}
                placeholder="Test payload, e.g.: 1' UNION SELECT * FROM users--" />
            </div>
            <motion.button className="btn bc" onClick={runTest} disabled={testLoading} whileTap={{ scale: 0.97 }}>
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
            </>)}
          </div>
        </div>
      </motion.div>

      {showModal && (
        <motion.div
          style={{ position:"fixed", inset:0, background:"var(--scrim)", zIndex:200, display:"flex", alignItems:"center", justifyContent:"center" }}
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
                <ScopeSelect />
              </div>
              <div className="fg2"><label className="flbl2">SRL DSL</label>
                <textarea className="rule-ta" value={editorDSL} onChange={e=>setEditorDSL(e.target.value)} style={{ minHeight:160 }} /></div>
              <div style={{ display:"flex", gap:8, justifyContent:"flex-end" }}>
                <button className="btn bg-btn" onClick={() => setShowModal(false)}>Cancel</button>
                <motion.button className="btn bp" onClick={createRule} disabled={saving} whileTap={{ scale: 0.97 }}>
                  {saving ? "Saving…" : "Create Rule"}
                </motion.button>
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </motion.div>
  );
}