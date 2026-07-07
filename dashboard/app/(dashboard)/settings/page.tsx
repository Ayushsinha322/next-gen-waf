"use client";
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import Toggle from "@/components/ui/Toggle";
import { api, type UserRow, type APIKeyRow, type NotificationChannel, type ChannelType, type ChannelConfig, type Severity, type ManagementTLSInfo } from "@/lib/api";
import { staggerContainer, fadeUp, spring } from "@/lib/animations";

const TABS = ["General","Auth & SSO","API Keys","Users & RBAC","Cluster","Notifications","Management TLS"];

export default function SettingsPage() {
  const [tab, setTab] = useState(0);
  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <motion.div variants={fadeUp} style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", gap:14 }}>
        <div>
          <div className="sec-title">⚙️ Settings</div>
          <div className="sec-sub">System configuration · Authentication · Team management · Cluster</div>
        </div>
        <motion.button className="btn bp btn-sm" onClick={() => showToast("Settings saved","s","💾")} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>💾 Save</motion.button>
      </motion.div>
      <motion.div className="tabs" variants={fadeUp}>
        {TABS.map((t,i) => <div key={i} className={`tab ${tab===i?"active":""}`} onClick={() => setTab(i)}>{t}</div>)}
      </motion.div>
      {tab === 0 && <GeneralTab />}
      {tab === 1 && <AuthTab />}
      {tab === 2 && <APIKeysTab />}
      {tab === 3 && <UsersTab />}
      {tab === 4 && <ClusterTab />}
      {tab === 5 && <NotificationsTab />}
      {tab === 6 && <ManagementTLSTab />}
    </motion.div>
  );
}

function GeneralTab() {
  return (
    <motion.div className="panel" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring}>
      <div className="pb">
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:16 }}>
          <div className="fg2"><label className="flbl2">Tenant Name</label><input className="fin2" defaultValue="Sentinel Security Labs" /></div>
          <div className="fg2"><label className="flbl2">Admin Email</label><input className="fin2" defaultValue="admin@sentinel.local" type="email" /></div>
          <div className="fg2"><label className="flbl2">Log Retention</label><select className="fin2 fsel2"><option>30 days</option><option>90 days</option><option>1 year</option></select></div>
          <div className="fg2"><label className="flbl2">Anomaly Threshold</label><input className="fin2" defaultValue="5" type="number" /></div>
          <div className="fg2"><label className="flbl2">Default WAF Mode</label><select className="fin2 fsel2"><option>BLOCKING</option><option>LEARNING</option><option>OFF</option></select></div>
          <div className="fg2"><label className="flbl2">Paranoia Level</label><select className="fin2 fsel2"><option>1 — Default</option><option>2 — Aggressive</option><option>3 — Paranoid</option><option>4 — Ultra</option></select></div>
        </div>
        {([
          ["Enable ML Anomaly Detection","Isolation Forest + Payload Classifier to score requests at Phase 2",true],
          ["Auto-reload on SIGHUP","Hot-reload config and rules without restarting the proxy daemon",true],
          ["OpenTelemetry Tracing","Export traces to OTEL collector at http://localhost:4317",true],
          ["Learning Mode Auto-Promote","Switch site to BLOCKING after 7 days of learning with <0.1% FP",false],
        ] as [string,string,boolean][]).map(([t,d,on]) => (
          <div key={t} className="srow">
            <div style={{flex:1}}><div className="srt">{t}</div><div className="srd">{d}</div></div>
            <div style={{flexShrink:0}}><Toggle defaultOn={on} /></div>
          </div>
        ))}
      </div>
    </motion.div>
  );
}

function AuthTab() {
  return (
    <motion.div className="panel" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring}>
      <div className="pb">
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:16 }}>
          <div className="fg2"><label className="flbl2">JWT Secret (HS256)</label><input className="fin2" defaultValue="••••••••••••••••••••••••••••••••" type="password" /></div>
          <div className="fg2"><label className="flbl2">Access Token TTL</label><select className="fin2 fsel2"><option>15 minutes</option><option>1 hour</option></select></div>
          <div className="fg2"><label className="flbl2">Refresh Token TTL</label><select className="fin2 fsel2"><option>1 day</option><option>7 days</option></select></div>
          <div className="fg2"><label className="flbl2">JWT Issuer</label><input className="fin2" defaultValue="sentinel-waf.corp.io" /></div>
        </div>
        {([
          ["Microsoft Entra ID (Azure AD)","Tenant: corp.onmicrosoft.com · Client ID configured","ACTIVE"],
          ["Google Workspace OIDC","Not configured","Set Up"],
          ["Okta Enterprise SSO","Not configured","Set Up"],
          ["SAML 2.0","SP Entity ID: https://sentinel-waf.corp.io/saml/metadata","Configure"],
        ] as [string,string,string][]).map(([t,d,btn]) => (
          <div key={t} className="srow">
            <div style={{flex:1}}><div className="srt">{t}</div><div className="srd">{d}</div></div>
            <motion.button className="btn bg-btn btn-xs" onClick={() => showToast(`${btn} clicked`,"i","🔧")} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.96 }}>{btn}</motion.button>
          </div>
        ))}
      </div>
    </motion.div>
  );
}

function APIKeysTab() {
  const [keys, setKeys]         = useState<APIKeyRow[]>([]);
  const [loading, setLoading]   = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName]   = useState("");
  const [newScope, setNewScope] = useState("read:all");
  const [creating, setCreating] = useState(false);
  const [revealKey, setRevealKey] = useState<string|null>(null);

  useEffect(() => {
    api.admin.apikeys.list()
      .then(r => setKeys(r.api_keys ?? []))
      .catch(() => showToast("Failed to load API keys","e","⚠️"))
      .finally(() => setLoading(false));
  }, []);

  async function generate() {
    if (!newName.trim()) { showToast("Key name required","w","⚠️"); return; }
    setCreating(true);
    try {
      const res = await api.admin.apikeys.create({ name: newName, scope: newScope });
      setRevealKey(res.api_key.key);
      setKeys(prev => [res.api_key as unknown as APIKeyRow, ...prev]);
      setNewName(""); setNewScope("read:all");
    } catch { showToast("Failed to generate key","e","⚠️"); }
    finally { setCreating(false); }
  }

  async function revoke(id: string, name: string) {
    if (!confirm(`Revoke API key "${name}"?`)) return;
    try {
      await api.admin.apikeys.revoke(id);
      setKeys(prev => prev.filter(k => k.id !== id));
      showToast(`Key "${name}" revoked`,"s","🔑");
    } catch { showToast("Failed to revoke","e","⚠️"); }
  }

  return (
    <motion.div className="panel" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring}>
      <div className="ph">
        <div className="ptitle">🔑 API Keys</div>
        <motion.button className="btn bp btn-sm" onClick={() => { setShowCreate(s=>!s); setRevealKey(null); }} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
          {showCreate ? "✕ Cancel" : "＋ Generate Key"}
        </motion.button>
      </div>
      {showCreate && (
        <div className="pb" style={{ borderBottom:"1px solid rgba(255,255,255,.06)", paddingBottom:14 }}>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
            <div className="fg2"><label className="flbl2">Key Name *</label>
              <input className="fin2" placeholder="CI/CD Pipeline" value={newName} onChange={e=>setNewName(e.target.value)} /></div>
            <div className="fg2"><label className="flbl2">Scope</label>
              <select className="fin2 fsel2" value={newScope} onChange={e=>setNewScope(e.target.value)}>
                <option value="read:all">read:all</option>
                <option value="read:all write:rules">read:all write:rules</option>
                <option value="read:logs">read:logs</option>
                <option value="write:all">write:all</option>
              </select></div>
          </div>
          <motion.button className="btn bp btn-sm" style={{marginTop:10}} onClick={generate} disabled={creating} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
            {creating ? "Generating…" : "🔑 Generate"}
          </motion.button>
          {revealKey && (
            <div className="code-block" style={{marginTop:10}}>
              <div style={{color:"var(--amber)",fontSize: 14,marginBottom:4}}>⚠ Copy now — shown only once</div>
              <code style={{color:"var(--green)",wordBreak:"break-all"}}>{revealKey}</code>
              <motion.button className="btn bg-btn btn-xs" style={{marginLeft:8}}
                onClick={() => { navigator.clipboard?.writeText(revealKey); showToast("Copied!","s","📋"); }} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.96 }}>Copy</motion.button>
            </div>
          )}
        </div>
      )}
      <div className="tw">
        {loading ? (
          <div style={{padding:"16px",textAlign:"center",fontSize: 13,color:"var(--text3)"}}>Loading…</div>
        ) : (
          <table>
            <thead><tr><th>Name</th><th>Key Preview</th><th>Scope</th><th>Expires</th><th>Last Used</th><th>Actions</th></tr></thead>
            <tbody>
              {keys.map((k, idx) => (
                <motion.tr key={k.id} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: idx * 0.02 }}>
                  <td>{k.name}</td>
                  <td className="td2">{k.preview}</td>
                  <td><span className="bdg bcy">{k.scope}</span></td>
                  <td className="td3">{k.expires_at ? new Date(k.expires_at).toLocaleDateString() : "—"}</td>
                  <td className="td3">{k.last_used}</td>
                  <td><motion.button className="btn bd btn-xs" onClick={() => revoke(k.id,k.name)} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.96 }}>Revoke</motion.button></td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </motion.div>
  );
}

function UsersTab() {
  const [users, setUsers]       = useState<UserRow[]>([]);
  const [loading, setLoading]   = useState(true);
  const [showInvite, setShowInvite] = useState(false);
  const [invEmail, setInvEmail] = useState("");
  const [invName, setInvName]   = useState("");
  const [invRole, setInvRole]   = useState("viewer");
  const [inviting, setInviting] = useState(false);

  useEffect(() => {
    api.admin.users.list()
      .then(r => setUsers(r.users ?? []))
      .catch(() => showToast("Failed to load users","e","⚠️"))
      .finally(() => setLoading(false));
  }, []);

  async function invite() {
    if (!invEmail.trim()) { showToast("Email required","w","⚠️"); return; }
    setInviting(true);
    try {
      const res = await api.admin.users.create({ email:invEmail, name:invName, role:invRole });
      setUsers(prev => [res.user, ...prev]);
      setShowInvite(false); setInvEmail(""); setInvName("");
      showToast(res.message,"s","📧");
    } catch { showToast("Failed to invite user","e","⚠️"); }
    finally { setInviting(false); }
  }

  function roleBadge(role:string) {
    const cls = role==="admin"||role==="owner" ? "br" : role==="editor" ? "ba" : "bgr";
    return <span className={`bdg ${cls}`}>{role.toUpperCase()}</span>;
  }

  function fmtLogin(ts:string|null) {
    if (!ts) return "Never";
    const diff = Date.now() - new Date(ts).getTime();
    if (diff<60000) return "Just now";
    if (diff<3600000) return Math.round(diff/60000)+"m ago";
    if (diff<86400000) return Math.round(diff/3600000)+"h ago";
    return Math.round(diff/86400000)+"d ago";
  }

  return (
    <motion.div className="panel" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring}>
      <div className="ph">
        <div className="ptitle">👥 Team Members</div>
        <motion.button className="btn bp btn-sm" onClick={() => setShowInvite(s=>!s)} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
          {showInvite ? "✕ Cancel" : "＋ Invite User"}
        </motion.button>
      </div>
      {showInvite && (
        <div className="pb" style={{ borderBottom:"1px solid rgba(255,255,255,.06)", paddingBottom:14 }}>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:12 }}>
            <div className="fg2"><label className="flbl2">Email *</label>
              <input className="fin2" placeholder="user@company.com" value={invEmail} onChange={e=>setInvEmail(e.target.value)} type="email" /></div>
            <div className="fg2"><label className="flbl2">Full Name</label>
              <input className="fin2" placeholder="Jane Smith" value={invName} onChange={e=>setInvName(e.target.value)} /></div>
            <div className="fg2"><label className="flbl2">Role</label>
              <select className="fin2 fsel2" value={invRole} onChange={e=>setInvRole(e.target.value)}>
                <option value="viewer">Viewer</option><option value="editor">Editor</option><option value="admin">Admin</option>
              </select></div>
          </div>
          <motion.button className="btn bp btn-sm" style={{marginTop:10}} onClick={invite} disabled={inviting} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
            {inviting ? "Sending…" : "📧 Send Invite"}
          </motion.button>
        </div>
      )}
      <div className="tw">
        {loading ? (
          <div style={{padding:"16px",textAlign:"center",fontSize: 13,color:"var(--text3)"}}>Loading…</div>
        ) : (
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>2FA</th><th>Last Login</th><th>Status</th></tr></thead>
            <tbody>
              {users.map((u, idx) => (
                <motion.tr key={u.id} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: idx * 0.02 }}>
                  <td>{u.name||"—"}</td>
                  <td className="td2">{u.email}</td>
                  <td>{roleBadge(u.role)}</td>
                  <td><span className={`bdg ${u.twofa?"bgg":"bgr"}`}>{u.twofa?"✓ TOTP":"✗ None"}</span></td>
                  <td className="td3">{fmtLogin(u.last_login)}</td>
                  <td><span className={`bdg ${u.status==="active"?"bgg":"bgr"}`}>{u.status.toUpperCase()}</span></td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </motion.div>
  );
}

function ClusterTab() {
  return (
    <motion.div className="panel" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring}>
      <div className="ph">
        <div className="ptitle">⚡ Cluster Status</div>
        <span className="bdg bgg"><span className="bdr" />Raft · 3 nodes</span>
      </div>
      <div className="pb">
        <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:10, marginBottom:16 }}>
          {([
            {role:"LEADER",  name:"cp-primary-01", ip:"10.0.0.10:8080", uptime:"14d 6h", term:4, idx:"18,422", cpu:"12%", mem:"284MB", leader:true},
            {role:"FOLLOWER",name:"cp-replica-02", ip:"10.0.0.11:8080", uptime:"14d 6h", term:4, idx:"18,422", cpu:"8%",  mem:"241MB", leader:false},
            {role:"FOLLOWER",name:"cp-replica-03", ip:"10.0.0.12:8080", uptime:"14d 6h", term:4, idx:"18,421", cpu:"9%",  mem:"258MB", leader:false},
          ]).map((n, idx) => (
            <motion.div key={n.name} className={`nodecard ${n.leader?"leader":""}`} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: idx * 0.08, ...spring }}>
              <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:10}}>
                <div className="sd g" />
                <span className="ncr" style={n.leader?{background:"rgba(200,0,30,.2)",color:"var(--red-b)",border:"1px solid var(--border)"}:{background:"rgba(0,200,240,.12)",color:"var(--cyan)",border:"1px solid rgba(0,200,240,.3)"}}>{n.role}</span>
              </div>
              <div className="ncn">{n.name}</div>
              <div className="ncs">IP: {n.ip}</div><div className="ncs">Uptime: {n.uptime}</div>
              <div className="ncs">Term: {n.term} · Log idx: {n.idx}</div>
              <div className="ncs" style={{color:"var(--green)",marginTop:5}}>CPU: {n.cpu} · Mem: {n.mem}</div>
            </motion.div>
          ))}
        </div>
        {([
          ["Quorum","2/3 required · 3/3 online","bgg","✓ HEALTHY"],
          ["Config Sync","Last push: 34 s ago · 5 data-plane nodes","bgg","✓ IN SYNC"],
          ["Data-Plane Nodes","dp-us-east-01, dp-us-west-01, dp-eu-01, dp-ap-01, dp-local-01","bcy","5 nodes"],
        ] as [string,string,string,string][]).map(([t,d,cls,val]) => (
          <div key={t} className="srow">
            <div style={{flex:1}}><div className="srt">{t}</div><div className="srd">{d}</div></div>
            <span className={`bdg ${cls}`}>{val}</span>
          </div>
        ))}
      </div>
    </motion.div>
  );
}

const CHANNEL_META: Record<ChannelType, { label: string; icon: string; blurb: string }> = {
  webhook: { label: "Webhook", icon: "🔗", blurb: "POST signed JSON to any HTTP endpoint (SIEM, SOAR, custom)" },
  slack:   { label: "Slack",   icon: "💬", blurb: "Slack incoming-webhook formatted message" },
  syslog:  { label: "Syslog",  icon: "📜", blurb: "RFC 5424 over UDP/TCP to a syslog collector" },
  cef:     { label: "CEF",     icon: "🛰️", blurb: "ArcSight Common Event Format over syslog (SIEM)" },
};
const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

const emptyForm = {
  name: "", type: "webhook" as ChannelType, min_severity: "medium" as Severity,
  url: "", secret: "", host: "", port: 514, protocol: "udp" as "udp" | "tcp",
};

function NotificationsTab() {
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [form, setForm] = useState({ ...emptyForm });

  async function load() {
    setLoading(true);
    try { setChannels((await api.notifications.list()).channels ?? []); }
    catch { showToast("Failed to load channels", "e", "⚠️"); }
    finally { setLoading(false); }
  }
  useEffect(() => { load(); }, []);

  function buildConfig(): ChannelConfig {
    if (form.type === "webhook") return { url: form.url.trim(), ...(form.secret ? { secret: form.secret } : {}) };
    if (form.type === "slack")   return { url: form.url.trim() };
    return { host: form.host.trim(), port: Number(form.port) || 514, protocol: form.protocol };
  }
  function formValid(): boolean {
    if (!form.name.trim()) return false;
    if (form.type === "webhook" || form.type === "slack") return /^https?:\/\//.test(form.url.trim());
    return !!form.host.trim();
  }

  async function create() {
    if (!formValid()) { showToast("Fill in the required fields", "e", "⚠️"); return; }
    setBusy("new");
    try {
      await api.notifications.create({ name: form.name.trim(), type: form.type, config: buildConfig(), min_severity: form.min_severity });
      showToast("Channel added", "s", "🔔");
      setForm({ ...emptyForm }); setAdding(false); await load();
    } catch (e) { showToast(e instanceof Error ? e.message : "Create failed", "e", "⚠️"); }
    finally { setBusy(null); }
  }
  async function test(id: string) {
    setBusy(id);
    try { const r = await api.notifications.test(id); showToast(r.ok ? "✓ Test alert delivered" : "Delivery failed", r.ok ? "s" : "e", r.ok ? "✅" : "⚠️"); await load(); }
    catch (e) { showToast(e instanceof Error ? e.message : "Delivery failed", "e", "⚠️"); await load(); }
    finally { setBusy(null); }
  }
  async function toggle(ch: NotificationChannel) {
    setBusy(ch.id);
    // Re-throw so the optimistic <Toggle> rolls back when the save fails.
    try { await api.notifications.update(ch.id, { enabled: !ch.enabled }); await load(); }
    catch (e) { showToast("Update failed", "e", "⚠️"); throw e; }
    finally { setBusy(null); }
  }
  async function del(ch: NotificationChannel) {
    if (!confirm(`Delete channel "${ch.name}"?`)) return;
    setBusy(ch.id);
    try { await api.notifications.delete(ch.id); showToast("Channel deleted", "s", "🗑️"); await load(); }
    catch { showToast("Delete failed", "e", "⚠️"); }
    finally { setBusy(null); }
  }

  const isNet = form.type === "syslog" || form.type === "cef";

  return (
    <motion.div className="panel" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring}>
      <div className="ph">
        <div className="ptitle">🔔 Notification Channels</div>
        <motion.button className="btn bc btn-sm" onClick={() => setAdding(a => !a)} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
          {adding ? "✕ Cancel" : "+ Add Channel"}
        </motion.button>
      </div>
      <div className="pb">
        <div style={{ fontSize: 13, color: "var(--text3)", lineHeight: 1.7, marginBottom: 12, fontFamily: "'Share Tech Mono',monospace" }}>
          Alerts (attack spikes, repeat offenders, critical blocks) are delivered to every enabled channel whose minimum severity the alert meets. Webhook payloads are optionally HMAC-SHA256 signed (<code>X-Sentinel-Signature</code>).
        </div>

        {adding && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} style={{ overflow: "hidden", marginBottom: 16, border: "1px solid var(--border, rgba(0,229,255,0.15))", borderRadius: 10, padding: 14 }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              <div className="fg2"><label className="flbl2">Name</label><input className="fin2" value={form.name} placeholder="prod-soc-webhook" onChange={e => setForm(f => ({ ...f, name: e.target.value }))} /></div>
              <div className="fg2"><label className="flbl2">Type</label>
                <select className="fin2 fsel2" value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value as ChannelType }))}>
                  {(Object.keys(CHANNEL_META) as ChannelType[]).map(t => <option key={t} value={t}>{CHANNEL_META[t].icon} {CHANNEL_META[t].label}</option>)}
                </select>
              </div>
            </div>
            <div style={{ fontSize: 12.5, color: "var(--text3)", margin: "2px 0 10px" }}>{CHANNEL_META[form.type].blurb}</div>

            {!isNet ? (
              <div style={{ display: "grid", gridTemplateColumns: form.type === "webhook" ? "1fr 1fr" : "1fr", gap: 10 }}>
                <div className="fg2"><label className="flbl2">{form.type === "slack" ? "Slack Webhook URL" : "Endpoint URL"}</label><input className="fin2" value={form.url} placeholder="https://…" onChange={e => setForm(f => ({ ...f, url: e.target.value }))} /></div>
                {form.type === "webhook" && <div className="fg2"><label className="flbl2">Signing Secret (optional)</label><input className="fin2" value={form.secret} placeholder="HMAC-SHA256 key" onChange={e => setForm(f => ({ ...f, secret: e.target.value }))} /></div>}
              </div>
            ) : (
              <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 10 }}>
                <div className="fg2"><label className="flbl2">Collector Host</label><input className="fin2" value={form.host} placeholder="siem.corp.io" onChange={e => setForm(f => ({ ...f, host: e.target.value }))} /></div>
                <div className="fg2"><label className="flbl2">Port</label><input className="fin2" type="number" value={form.port} onChange={e => setForm(f => ({ ...f, port: Number(e.target.value) }))} /></div>
                <div className="fg2"><label className="flbl2">Protocol</label><select className="fin2 fsel2" value={form.protocol} onChange={e => setForm(f => ({ ...f, protocol: e.target.value as "udp" | "tcp" }))}><option value="udp">UDP</option><option value="tcp">TCP</option></select></div>
              </div>
            )}
            <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 10, alignItems: "end", marginTop: 4 }}>
              <div className="fg2"><label className="flbl2">Minimum severity</label>
                <select className="fin2 fsel2" value={form.min_severity} onChange={e => setForm(f => ({ ...f, min_severity: e.target.value as Severity }))}>
                  {SEVERITIES.map(s => <option key={s} value={s}>{s.toUpperCase()}</option>)}
                </select>
              </div>
              <button className="btn bp btn-sm" disabled={busy === "new"} onClick={create}>{busy === "new" ? "Saving…" : "✓ Add Channel"}</button>
            </div>
          </motion.div>
        )}

        {loading ? (
          <div style={{ padding: 24, textAlign: "center", fontSize: 13, color: "var(--text3)", fontFamily: "'Share Tech Mono',monospace" }}>Loading channels…</div>
        ) : channels.length === 0 ? (
          <div style={{ padding: 24, textAlign: "center", fontSize: 13, color: "var(--text3)", fontFamily: "'Share Tech Mono',monospace" }}>No channels configured. Add one to start delivering alerts to your SOC.</div>
        ) : channels.map(ch => (
          <div key={ch.id} className="srow">
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="srt">{CHANNEL_META[ch.type]?.icon} {ch.name} <span className="bdg bcy" style={{ marginLeft: 6 }}>{ch.type.toUpperCase()}</span> <span className="bdg" style={{ marginLeft: 4 }}>≥ {ch.min_severity.toUpperCase()}</span></div>
              <div className="srd" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {ch.type === "webhook" || ch.type === "slack" ? ch.config.url : `${ch.config.host}:${ch.config.port}/${ch.config.protocol}`}
                {ch.last_status && <span style={{ marginLeft: 8, color: ch.last_status === "ok" ? "var(--green)" : "#ef4444" }}>· last: {ch.last_status === "ok" ? "✓ ok" : ch.last_status}</span>}
              </div>
            </div>
            <div style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
              <button className="btn bg-btn btn-xs" disabled={busy === ch.id} onClick={() => test(ch.id)}>{busy === ch.id ? "…" : "Test"}</button>
              <Toggle defaultOn={ch.enabled} onChange={() => toggle(ch)} />
              <button className="btn bg-btn btn-xs" style={{ color: "#ef4444" }} disabled={busy === ch.id} onClick={() => del(ch)}>🗑️</button>
            </div>
          </div>
        ))}
      </div>
    </motion.div>
  );
}

// ── Management TLS ─────────────────────────────────────────────────────────────
function MgmtField({ label, value, mono }: { label: string; value?: string; mono?: boolean }) {
  return (
    <div className="fg2">
      <label className="flbl2">{label}</label>
      <div style={{ fontFamily: mono ? "monospace" : undefined, fontSize: mono ? 11 : 13, wordBreak: "break-all" }}>
        {value && value.length ? value : "—"}
      </div>
    </div>
  );
}

function ManagementTLSTab() {
  const [info, setInfo] = useState<ManagementTLSInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [cert, setCert] = useState("");
  const [pkey, setPkey] = useState("");
  const [ca, setCa] = useState("");
  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [warnings, setWarnings] = useState<string[]>([]);

  async function load() {
    setLoading(true);
    try { setInfo(await api.managementTls.get()); }
    catch { showToast("Failed to load management TLS", "e", "⚠️"); }
    finally { setLoading(false); }
  }
  useEffect(() => { load(); }, []);

  const fmtDate = (u?: number) =>
    u ? new Date(u * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "—";
  const daysLeft = (u?: number) => (u ? Math.floor((u * 1000 - Date.now()) / 86_400_000) : null);

  async function upload() {
    if (!cert.trim() || !pkey.trim()) { showToast("Paste both the certificate and the private key", "e", "⚠️"); return; }
    setBusy("upload"); setWarnings([]);
    try {
      const r = await api.managementTls.upload({
        cert_pem: cert, key_pem: pkey,
        ca_bundle_pem: ca.trim() || undefined,
        name: name.trim() || undefined,
        expected_host: host.trim() || undefined,
      });
      setWarnings(r.warnings ?? []);
      showToast("Management certificate installed — applies on the next connection", "s", "🔐");
      setCert(""); setPkey(""); setCa("");
      await load();
    } catch (e) {
      showToast(e instanceof Error ? e.message : "Upload failed", "e", "⛔");
    } finally { setBusy(null); }
  }

  async function revert() {
    if (!confirm("Revert to the self-signed default management certificate?")) return;
    setBusy("revert");
    try { await api.managementTls.revert(); showToast("Reverted to self-signed default", "s", "↩️"); await load(); }
    catch { showToast("Revert failed", "e", "⚠️"); }
    finally { setBusy(null); }
  }

  const d = daysLeft(info?.expires_at);
  return (
    <motion.div className="panel" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring}>
      <div className="ph">
        <div className="ptitle">🔐 Management Console Certificate</div>
        {info && !info.self_signed && (
          <motion.button className="btn bg-btn btn-sm" disabled={busy === "revert"} onClick={revert}
            whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>↩️ Revert to self-signed</motion.button>
        )}
      </div>
      <div className="pb">
        <p className="sec-sub" style={{ marginTop: 0 }}>
          The certificate the WAF presents on its <b>management endpoint</b> (this admin console). Served by
          Sentinel&apos;s own engine — no third-party proxy. Customer-website certificates are separate and live
          under <b>Certificates</b>.
        </p>

        {loading ? (
          <div className="sec-sub">Loading…</div>
        ) : info?.self_signed ? (
          <div className="panel" style={{ background: "rgba(245,158,11,.08)", borderColor: "var(--amber)" }}>
            <div className="pb">
              <b>⚠️ Self-signed default in use</b>
              <div className="sec-sub">
                Browsers warn until you install a trusted certificate below (or import the Sentinel root CA from
                the Certificates page). Traffic is encrypted either way.
              </div>
            </div>
          </div>
        ) : (
          <>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2,1fr)", gap: 10 }}>
              <MgmtField label="Profile / Subject" value={info?.name} />
              <MgmtField label="Issuer" value={info?.issuer} />
              <MgmtField label="Valid until" value={`${fmtDate(info?.expires_at)}${d !== null ? ` · ${d}d left` : ""}`} />
              <MgmtField label="Key type" value={info?.key_type} />
              <MgmtField label="SAN" value={(info?.san || []).join(", ")} />
              <MgmtField label="Fingerprint (SHA-256)" value={info?.fingerprint} mono />
            </div>
            {d !== null && d <= 30 && (
              <div style={{ color: "var(--red)", fontSize: 15, marginTop: 8 }}>⚠️ Expires in {d} day(s) — plan a rotation.</div>
            )}
          </>
        )}

        <div style={{ marginTop: 18 }}>
          <div className="ptitle" style={{ fontSize: 16, marginBottom: 8 }}>Upload a new management certificate</div>
          <div className="fg2"><label className="flbl2">Profile name (optional)</label>
            <input className="fin2" value={name} placeholder="Company management cert" onChange={e => setName(e.target.value)} /></div>
          <div className="fg2"><label className="flbl2">Certificate (PEM — leaf first, then any intermediates)</label>
            <textarea className="fin2" style={{ minHeight: 120, fontFamily: "monospace" }} value={cert}
              placeholder="-----BEGIN CERTIFICATE-----" onChange={e => setCert(e.target.value)} /></div>
          <div className="fg2"><label className="flbl2">Private key (PEM)</label>
            <textarea className="fin2" style={{ minHeight: 90, fontFamily: "monospace" }} value={pkey}
              placeholder="-----BEGIN PRIVATE KEY-----" onChange={e => setPkey(e.target.value)} /></div>
          <div className="fg2"><label className="flbl2">CA bundle (PEM, optional — enables chain verification)</label>
            <textarea className="fin2" style={{ minHeight: 70, fontFamily: "monospace" }} value={ca}
              placeholder="-----BEGIN CERTIFICATE----- (roots / intermediates)" onChange={e => setCa(e.target.value)} /></div>
          <div className="fg2"><label className="flbl2">Expected hostname / IP (optional — warns on SAN mismatch)</label>
            <input className="fin2" value={host} placeholder="172.16.21.71" onChange={e => setHost(e.target.value)} /></div>

          <div className="sec-sub" style={{ fontSize: 14, margin: "4px 0 10px" }}>
            🔒 The key is validated (matches the cert, in-date, has a SAN), stored only on the WAF node, and is
            never written to the database, logged, or shown again.
          </div>

          {warnings.length > 0 && (
            <div className="panel" style={{ background: "rgba(245,158,11,.08)", borderColor: "var(--amber)", marginBottom: 10 }}>
              <div className="pb">
                <b>Installed with warnings:</b>
                <ul style={{ margin: "6px 0 0 18px" }}>{warnings.map((w, i) => <li key={i} className="sec-sub">{w}</li>)}</ul>
              </div>
            </div>
          )}

          <button className="btn bp btn-sm" disabled={busy === "upload"} onClick={upload}>
            {busy === "upload" ? "Validating…" : "🔐 Validate & Install"}
          </button>
        </div>
      </div>
    </motion.div>
  );
}