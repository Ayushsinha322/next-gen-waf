"use client";
import { useState, useEffect } from "react";
import { showToast } from "@/components/ui/Toast";
import Toggle from "@/components/ui/Toggle";
import { api, type UserRow, type APIKeyRow } from "@/lib/api";

const TABS = ["General","Auth & SSO","API Keys","Users & RBAC","Cluster","Notifications"];

export default function SettingsPage() {
  const [tab, setTab] = useState(0);
  return (
    <div className="sec">
      <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", gap:14 }}>
        <div>
          <div className="sec-title">⚙️ Settings</div>
          <div className="sec-sub">System configuration · Authentication · Team management · Cluster</div>
        </div>
        <button className="btn bp btn-sm" onClick={() => showToast("Settings saved","s","💾")}>💾 Save</button>
      </div>
      <div className="tabs">
        {TABS.map((t,i) => <div key={i} className={`tab ${tab===i?"active":""}`} onClick={() => setTab(i)}>{t}</div>)}
      </div>
      {tab === 0 && <GeneralTab />}
      {tab === 1 && <AuthTab />}
      {tab === 2 && <APIKeysTab />}
      {tab === 3 && <UsersTab />}
      {tab === 4 && <ClusterTab />}
      {tab === 5 && <NotificationsTab />}
    </div>
  );
}

function GeneralTab() {
  return (
    <div className="panel">
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
    </div>
  );
}

function AuthTab() {
  return (
    <div className="panel">
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
            <button className="btn bg-btn btn-xs" onClick={() => showToast(`${btn} clicked`,"i","🔧")}>{btn}</button>
          </div>
        ))}
      </div>
    </div>
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
    <div className="panel">
      <div className="ph">
        <div className="ptitle">🔑 API Keys</div>
        <button className="btn bp btn-sm" onClick={() => { setShowCreate(s=>!s); setRevealKey(null); }}>
          {showCreate ? "✕ Cancel" : "＋ Generate Key"}
        </button>
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
          <button className="btn bp btn-sm" style={{marginTop:10}} onClick={generate} disabled={creating}>
            {creating ? "Generating…" : "🔑 Generate"}
          </button>
          {revealKey && (
            <div className="code-block" style={{marginTop:10}}>
              <div style={{color:"var(--amber)",fontSize:10,marginBottom:4}}>⚠ Copy now — shown only once</div>
              <code style={{color:"var(--green)",wordBreak:"break-all"}}>{revealKey}</code>
              <button className="btn bg-btn btn-xs" style={{marginLeft:8}}
                onClick={() => { navigator.clipboard?.writeText(revealKey); showToast("Copied!","s","📋"); }}>Copy</button>
            </div>
          )}
        </div>
      )}
      <div className="tw">
        {loading ? (
          <div style={{padding:"16px",textAlign:"center",fontSize:11,color:"var(--text3)"}}>Loading…</div>
        ) : (
          <table>
            <thead><tr><th>Name</th><th>Key Preview</th><th>Scope</th><th>Expires</th><th>Last Used</th><th>Actions</th></tr></thead>
            <tbody>
              {keys.map(k => (
                <tr key={k.id}>
                  <td>{k.name}</td>
                  <td className="td2">{k.preview}</td>
                  <td><span className="bdg bcy">{k.scope}</span></td>
                  <td className="td3">{k.expires_at ? new Date(k.expires_at).toLocaleDateString() : "—"}</td>
                  <td className="td3">{k.last_used}</td>
                  <td><button className="btn bd btn-xs" onClick={() => revoke(k.id,k.name)}>Revoke</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
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
    <div className="panel">
      <div className="ph">
        <div className="ptitle">👥 Team Members</div>
        <button className="btn bp btn-sm" onClick={() => setShowInvite(s=>!s)}>
          {showInvite ? "✕ Cancel" : "＋ Invite User"}
        </button>
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
                <option value="viewer">Viewer</option>
                <option value="editor">Editor</option>
                <option value="admin">Admin</option>
              </select></div>
          </div>
          <button className="btn bp btn-sm" style={{marginTop:10}} onClick={invite} disabled={inviting}>
            {inviting ? "Sending…" : "📧 Send Invite"}
          </button>
        </div>
      )}
      <div className="tw">
        {loading ? (
          <div style={{padding:"16px",textAlign:"center",fontSize:11,color:"var(--text3)"}}>Loading…</div>
        ) : (
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>2FA</th><th>Last Login</th><th>Status</th></tr></thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}>
                  <td>{u.name||"—"}</td>
                  <td className="td2">{u.email}</td>
                  <td>{roleBadge(u.role)}</td>
                  <td><span className={`bdg ${u.twofa?"bgg":"bgr"}`}>{u.twofa?"✓ TOTP":"✗ None"}</span></td>
                  <td className="td3">{fmtLogin(u.last_login)}</td>
                  <td><span className={`bdg ${u.status==="active"?"bgg":"bgr"}`}>{u.status.toUpperCase()}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function ClusterTab() {
  return (
    <div className="panel">
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
          ]).map(n => (
            <div key={n.name} className={`nodecard ${n.leader?"leader":""}`}>
              <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:10}}>
                <div className="sd g" />
                <span className="ncr" style={n.leader?{background:"rgba(200,0,30,.2)",color:"var(--red-b)",border:"1px solid var(--border)"}:{background:"rgba(0,200,240,.12)",color:"var(--cyan)",border:"1px solid rgba(0,200,240,.3)"}}>
                  {n.role}
                </span>
              </div>
              <div className="ncn">{n.name}</div>
              <div className="ncs">IP: {n.ip}</div>
              <div className="ncs">Uptime: {n.uptime}</div>
              <div className="ncs">Term: {n.term} · Log idx: {n.idx}</div>
              <div className="ncs" style={{color:"var(--green)",marginTop:5}}>CPU: {n.cpu} · Mem: {n.mem}</div>
            </div>
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
    </div>
  );
}

function NotificationsTab() {
  return (
    <div className="panel">
      <div className="pb">
        {([
          ["Email Alerts","Send critical alerts to admin@sentinel.local",true],
          ["Slack Notifications","Webhook: https://hooks.slack.com/services/T••••/B••••/••••",true],
          ["PagerDuty","Escalate CRITICAL alerts to on-call",false],
          ["Webhook (Custom)","POST to custom endpoint for SIEM integration",false],
        ] as [string,string,boolean][]).map(([t,d,on]) => (
          <div key={t} className="srow">
            <div style={{flex:1}}><div className="srt">{t}</div><div className="srd">{d}</div></div>
            <Toggle defaultOn={on} />
          </div>
        ))}
        <div className="fg2" style={{marginTop:8}}>
          <label className="flbl2">Custom Webhook URL</label>
          <input className="fin2" placeholder="https://your-siem.corp.io/events" type="url" />
        </div>
      </div>
    </div>
  );
}
