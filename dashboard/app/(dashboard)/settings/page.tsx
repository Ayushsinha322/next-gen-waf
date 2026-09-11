"use client";
import { useT, SUPPORTED_LOCALES, type Locale } from "@/lib/i18n";
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import Toggle from "@/components/ui/Toggle";
import { api, type UserRow, type APIKeyRow, type NotificationChannel, type ChannelType, type ChannelConfig, type Severity, type ManagementTLSInfo, type ClusterHealth } from "@/lib/api";
import { staggerContainer, fadeUp, spring, tweenFast } from "@/lib/animations";
import { logout, getUser } from "@/lib/auth";
import { PRODUCT_NAME } from "@/lib/version";

const TABS = ["General","Auth & SSO","API Keys","Users & RBAC","Cluster","Notifications","Management TLS"];

/** Slug per tab so other pages can deep-link (e.g. the Alerts page sends an
 *  operator with no delivery channel straight to /settings?tab=notifications). */
const TAB_SLUGS = ["general","auth","api-keys","users","cluster","notifications","management-tls"];

export default function SettingsPage() {
  const [tab, setTab] = useState(0);
  // Read ?tab= after mount (window only) rather than useSearchParams, which
  // would force a Suspense boundary on this statically-rendered client page.
  useEffect(() => {
    try {
      const want = new URLSearchParams(window.location.search).get("tab");
      const i = want ? TAB_SLUGS.indexOf(want) : -1;
      if (i >= 0) setTab(i);
    } catch { /* no window */ }
  }, []);
  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <motion.div variants={fadeUp} style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", gap:14 }}>
        <div>
          <div className="sec-title">⚙️ Settings</div>
          <div className="sec-sub">System configuration · Authentication · Team management · Cluster</div>
        </div>
      </motion.div>
      <motion.div className="tabs" variants={fadeUp}>
        {TABS.map((t,i) => <div key={i} className={`tab ${tab===i?"active":""}`} onClick={() => { setTab(i); try { history.replaceState(null, "", `/settings?tab=${TAB_SLUGS[i]}`); } catch { /* */ } }}>{t}</div>)}
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

/**
 * General and Auth & SSO were the two lead tabs of the settings screen and both
 * were entirely non-functional.
 *
 * General had six `defaultValue` inputs and four `<Toggle defaultOn>` with no
 * state, no handlers and no endpoint behind them: an evaluator could change
 * "Default WAF Mode" or "Paranoia Level", navigate away, and silently lose it —
 * or worse, believe they had changed live protection. Those two fields are
 * per-site policy and are edited in Sites, not here.
 *
 * Auth advertised four SSO integrations (Entra, Google Workspace, Okta, SAML 2.0)
 * whose buttons called showToast, and published a fabricated SP Entity ID at
 * https://sentinel-waf.corp.io/saml/metadata. In reality the control plane
 * implements ONE generic OIDC provider — which is what covers Entra, Google and
 * Okta — configured by environment variable, and no SAML at all.
 *
 * Both tabs now report what is true and offer no control that does nothing.
 */
function KV({ label, value, mono = true }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "220px 1fr", gap: 12, padding: "9px 0", borderBottom: "1px solid var(--border2)" }}>
      <div style={{ fontSize: "var(--fs-label)", color: "var(--text3)", textTransform: "uppercase", letterSpacing: "var(--tr-wide)" }}>{label}</div>
      <div style={{ fontSize: "var(--fs-sm)", color: "var(--text)", fontFamily: mono ? "var(--font-mono)" : undefined, overflowWrap: "anywhere" }}>{value}</div>
    </div>
  );
}

function Note({ children, tone = "info" }: { children: React.ReactNode; tone?: "info" | "warn" }) {
  const c = tone === "warn"
    ? ["rgba(255,176,32,.07)", "rgba(255,176,32,.25)"]
    : ["rgba(0,212,255,.06)", "rgba(0,212,255,.18)"];
  return (
    <div style={{
      padding: "11px 14px", background: c[0], border: `1px solid ${c[1]}`,
      borderRadius: "var(--r2)", fontSize: "var(--fs-sm)", color: "var(--text2)",
      lineHeight: 1.65, marginBottom: 14,
    }}>{children}</div>
  );
}

function GeneralTab() {
  const [waf, setWaf] = useState<{ waf_running: boolean; uptime_secs?: number; sites?: number; listeners?: string[]; upstreams_healthy?: number; upstreams_total?: number; http3?: { enabled: boolean; advertise_port?: number } } | null>(null);
  const [cluster, setCluster] = useState<ClusterHealth | null>(null);
  const [store, setStore] = useState<{ configured: boolean; reachable: boolean; events?: number; error?: string } | null>(null);
  const [errs, setErrs] = useState<string[]>([]);

  useEffect(() => {
    let alive = true;
    const note = (what: string) => (e: unknown) => {
      if (alive) setErrs(p => [...p, `${what}: ${e instanceof Error ? e.message : "failed"}`]);
    };
    api.waf.status().then(r => alive && setWaf(r)).catch(note("data plane"));
    api.cluster.health().then(r => alive && setCluster(r)).catch(note("cluster"));
    api.events.status().then(r => alive && setStore(r)).catch(note("event store"));
    return () => { alive = false; };
  }, []);

  const uptime = (secs?: number) => {
    if (secs === undefined || secs === null) return "—";
    const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600), m = Math.floor((secs % 3600) / 60);
    return d > 0 ? `${d}d ${h}h ${m}m` : h > 0 ? `${h}h ${m}m` : `${m}m`;
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={tweenFast}
      style={{ display: "grid", gap: 14 }}>

      {errs.length > 0 && (
        <div className="panel"><div className="pb">
          <div style={{ fontSize: "var(--fs-sm)", color: "var(--red)" }}>
            {errs.map((e, i) => <div key={i}>Could not read {e}</div>)}
          </div>
        </div></div>
      )}

      <div className="panel">
        <div className="ph"><div className="ptitle">Data plane</div>
          <span className={`bdg ${waf?.waf_running ? "bgg" : "br"}`}>
            {waf ? (waf.waf_running ? "RUNNING" : "STOPPED") : "…"}
          </span>
        </div>
        <div className="pb">
          <KV label="Uptime" value={uptime(waf?.uptime_secs)} />
          <KV label="Protected sites" value={waf?.sites ?? "…"} />
          <KV label="Upstream health" value={
            waf ? `${waf.upstreams_healthy ?? 0} / ${waf.upstreams_total ?? 0} healthy` : "…"} />
          <KV label="Listeners" value={waf?.listeners?.length ? waf.listeners.join("   ") : "…"} />
        </div>
      </div>

      <div className="panel">
        <div className="ph"><div className="ptitle">Console language</div></div>
        <div className="pb">
          <LanguagePicker />
          <KV label="HTTP/3 (QUIC)" value={
            waf?.http3 ? (waf.http3.enabled ? `enabled · advertised :${waf.http3.advertise_port ?? "?"}` : "disabled") : "…"} />
        </div>
      </div>

      <div className="panel">
        <div className="ph"><div className="ptitle">Cluster</div>
          {cluster && <span className={`bdg ${cluster.overall === "healthy" ? "bgg" : cluster.overall === "degraded" ? "ba" : "br"}`}>
            {cluster.overall.toUpperCase()}</span>}
        </div>
        <div className="pb">
          <KV label="Protection active" value={cluster ? (cluster.protection_active ? "yes" : "NO") : "…"} />
          <KV label="Data-plane nodes" value={cluster
            ? `${cluster.data_plane.healthy} healthy · ${cluster.data_plane.degraded} degraded · ${cluster.data_plane.down} down  (of ${cluster.data_plane.total})`
            : "…"} />
          <KV label="Resilience budget" value={cluster ? `${cluster.data_plane.resilience_budget} node(s) may fail` : "…"} />
          <KV label="Control plane" value={cluster
            ? (cluster.control_plane.enabled
                ? `${cluster.control_plane.healthy}/${cluster.control_plane.total} up · this node: ${cluster.control_plane.role ?? "unknown"}`
                : "single node")
            : "…"} />
        </div>
      </div>

      <div className="panel">
        <div className="ph"><div className="ptitle">Event store (ClickHouse)</div>
          {store && <span className={`bdg ${store.configured && store.reachable ? "bgg" : "ba"}`}>
            {store.configured ? (store.reachable ? "REACHABLE" : "UNREACHABLE") : "NOT CONFIGURED"}</span>}
        </div>
        <div className="pb">
          <KV label="Configured" value={store ? String(store.configured) : "…"} />
          <KV label="Reachable" value={store ? String(store.reachable) : "…"} />
          <KV label="Stored events" value={store?.events?.toLocaleString() ?? "—"} />
          {store?.error && <KV label="Error" value={store.error} />}
        </div>
      </div>

      <div className="panel">
        <div className="ph"><div className="ptitle">Where settings actually live</div></div>
        <div className="pb">
          <Note>
            <strong>Protection settings are per site.</strong> WAF mode, paranoia level,
            anomaly threshold, rate limits, bot detection and ML sensitivity all belong to
            an individual site and are edited in <strong>Sites → Edit</strong>, where the
            change is dry-run validated and a rollback point is written. This tab used to
            show global copies of those fields that were never saved anywhere.
          </Note>
          <Note tone="warn">
            <strong>Log retention, tracing and the data-plane config file</strong> are set
            where the stack is deployed, via environment variables and
            <code style={{ fontFamily: "var(--font-mono)" }}> sentinel.proxy.yaml</code> —
            there is no tenant-settings API, so this console does not pretend to own them.
          </Note>
        </div>
      </div>
    </motion.div>
  );
}

function AuthTab() {
  return (
    <motion.div className="panel" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={tweenFast}>
      <div className="pb">
        <div style={{ fontSize: "var(--fs-h3)", fontWeight: 600, color: "var(--text)", margin: "4px 0 6px" }}>
          Single sign-on
        </div>
        <Note>
          Sentinel implements <strong>one generic OpenID Connect provider</strong>,
          which is what integrates Microsoft Entra ID, Google Workspace, Okta and
          any other OIDC-compliant IdP. There is no separate connector per vendor,
          and <strong>SAML 2.0 is not implemented</strong> — this tab used to list
          four providers and publish a SAML metadata URL that did not exist.
        </Note>

        <KV label="Mechanism" value="OpenID Connect (Authorization Code)" />
        <KV label="Login endpoint" value="/api/v1/auth/oidc/login" />
        <KV label="Callback endpoint" value="/api/v1/auth/oidc/callback" />
        <KV label="Configured by" value="environment variables on the control plane" />

        <div style={{ fontSize: "var(--fs-h3)", fontWeight: 600, color: "var(--text)", margin: "18px 0 6px" }}>
          Required environment
        </div>
        <div style={{
          padding: "12px 14px", background: "var(--term-bg)", borderRadius: "var(--r2)",
          border: "1px solid var(--border2)", fontFamily: "var(--font-mono)",
          fontSize: "var(--fs-code)", lineHeight: 1.8, color: "var(--term-fg)",
        }}>
          <div><span style={{ color: "var(--term-blue)" }}>SENTINEL_OIDC_ISSUER</span>          <span style={{ color: "var(--term-dim)" }}># required, must be https://</span></div>
          <div><span style={{ color: "var(--term-blue)" }}>SENTINEL_OIDC_CLIENT_SECRET</span>   <span style={{ color: "var(--term-dim)" }}># required</span></div>
          <div><span style={{ color: "var(--term-blue)" }}>SENTINEL_OIDC_CLIENT_ID</span>       <span style={{ color: "var(--term-dim)" }}># default: sentinel</span></div>
          <div><span style={{ color: "var(--term-blue)" }}>SENTINEL_OIDC_REDIRECT_URL</span>    <span style={{ color: "var(--term-dim)" }}># must match the IdP</span></div>
          <div><span style={{ color: "var(--term-blue)" }}>SENTINEL_OIDC_ALLOWED_DOMAINS</span> <span style={{ color: "var(--term-dim)" }}># optional, comma-separated</span></div>
        </div>
        <Note tone="warn">
          SSO <strong>fails closed</strong>: if the issuer is unset, the secret is
          unset, or the issuer is not HTTPS, OIDC login is disabled entirely rather
          than falling back to something weaker. Password login with the local user
          store continues to work either way.
        </Note>

        <div style={{ fontSize: "var(--fs-h3)", fontWeight: 600, color: "var(--text)", margin: "18px 0 6px" }}>
          Session tokens
        </div>
        <Note>
          Token lifetimes and the signing secret are control-plane deployment
          settings and are deliberately not editable from a web console — an
          attacker with a session here could otherwise mint long-lived credentials
          or rotate the signing key. Manage users and their roles in{" "}
          <strong>Users &amp; RBAC</strong>, and machine credentials in{" "}
          <strong>API Keys</strong>.
        </Note>
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
      // The API takes `scopes` as an array and a separate `role`. The picker
      // offers space-separated scope strings ("read:all write:rules"), so split
      // them; a key that can write needs more than the default viewer role.
      const scopes = newScope.split(/\s+/).filter(Boolean);
      const role = scopes.some(s => s.startsWith("write:")) ? "editor" : "viewer";
      const res = await api.admin.apikeys.create({ name: newName, role, scopes });
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
    <motion.div className="panel" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={tweenFast}>
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
  const [invPass, setInvPass]   = useState("");
  const [inviting, setInviting] = useState(false);
  // id of the user whose reset link is currently being sent
  const [resetting, setResetting] = useState<string | null>(null);
  // null = not yet known. The reset button is only disabled once we KNOW mail is
  // unconfigured, so a slow status call never blocks a working action.
  const [mailReady, setMailReady] = useState<boolean | null>(null);
  const [mailHost, setMailHost]   = useState("");

  const loadUsers = () =>
    api.admin.users.list()
      .then(r => setUsers(r.users ?? []))
      .catch(() => showToast("Failed to load users","e","⚠️"))
      .finally(() => setLoading(false));

  useEffect(() => {
    loadUsers();
    api.mail.status()
      .then(r => { setMailReady(r.mail.password_reset_ready); setMailHost(r.mail.host); })
      .catch(() => setMailReady(null));
  }, []);

  async function sendReset(id: string, email: string) {
    setResetting(id);
    try {
      const res = await api.admin.users.sendResetLink(id);
      showToast(res.message ?? `Reset link sent to ${email}`, "s", "✉️");
    } catch (e) {
      // The API says exactly what is wrong (SMTP unset, no public URL, relay
      // refused). Passing it through is the difference between an operator
      // fixing it in a minute and filing a bug.
      showToast(e instanceof Error ? e.message : "Could not send reset link", "e", "⚠️");
    } finally { setResetting(null); }
  }

  // Creates a user with an initial password. The account holder can change it
  // themselves afterwards (Your password, below), and an administrator can mail
  // them a reset link — so this password is a starting credential, not a
  // permanent one as it used to be.
  //
  // This used to POST {email,name,role} with no password. The API binds password
  // as `required,min=12`, so every attempt was rejected 400 and the catch below
  // reported a flat "Failed to invite user", hiding the reason.
  async function invite() {
    if (!invEmail.trim()) { showToast("Email required","w","⚠️"); return; }
    if (invPass.length < 12) { showToast("Password must be at least 12 characters","w","⚠️"); return; }
    setInviting(true);
    try {
      const res = await api.admin.users.create({ email:invEmail, name:invName, role:invRole, password:invPass });
      setUsers(prev => [res.user, ...prev]);
      setShowInvite(false); setInvEmail(""); setInvName(""); setInvPass("");
      showToast(res.message ?? "User created","s","✅");
    } catch (e) {
      // Surface what the API actually said. A generic message here is what let a
      // permanently-failing form look like an intermittent glitch.
      showToast(e instanceof Error ? e.message : "Failed to create user","e","⚠️");
    }
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
    <>
    <ChangePasswordCard />
    <TwoFactorCard users={users} onChanged={loadUsers} />

    {/* Password recovery depends entirely on outbound mail, so its real state
        belongs here rather than being discovered when someone is locked out. */}
    {mailReady === false && (
      <Note tone="warn">
        <strong>Password recovery is unavailable.</strong> No SMTP relay is configured,
        so &ldquo;Forgot password?&rdquo; cannot deliver a link and the reset buttons below
        are disabled. Set <code>SENTINEL_SMTP_HOST</code>, <code>SENTINEL_SMTP_FROM</code> and{" "}
        <code>SENTINEL_PUBLIC_URL</code> in the deployment&apos;s <code>.env</code>, then
        recreate the control plane.
      </Note>
    )}
    {mailReady === true && (
      <Note>
        Password recovery is active — mail relays through <code>{mailHost}</code>. Users
        can reset from the sign-in page, and you can email any account a single-use link below.
      </Note>
    )}

    <motion.div className="panel" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={tweenFast}>
      <div className="ph">
        <div className="ptitle">👥 Team Members</div>
        <motion.button className="btn bp btn-sm" onClick={() => setShowInvite(s=>!s)} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
          {showInvite ? "✕ Cancel" : "＋ Add User"}
        </motion.button>
      </div>
      {showInvite && (
        <div className="pb" style={{ borderBottom:"1px solid rgba(255,255,255,.06)", paddingBottom:14 }}>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr 1fr", gap:12 }}>
            <div className="fg2"><label className="flbl2">Email *</label>
              <input className="fin2" placeholder="user@company.com" value={invEmail} onChange={e=>setInvEmail(e.target.value)} type="email" /></div>
            <div className="fg2"><label className="flbl2">Full Name</label>
              <input className="fin2" placeholder="Jane Smith" value={invName} onChange={e=>setInvName(e.target.value)} /></div>
            <div className="fg2"><label className="flbl2">Password *</label>
              <input className="fin2" placeholder="min 12 characters" value={invPass} onChange={e=>setInvPass(e.target.value)} type="password" autoComplete="new-password" /></div>
            <div className="fg2"><label className="flbl2">Role</label>
              <select className="fin2 fsel2" value={invRole} onChange={e=>setInvRole(e.target.value)}>
                <option value="viewer">Viewer</option><option value="editor">Editor</option><option value="admin">Admin</option>
              </select></div>
          </div>
          {/* Creating an account still sends nothing — the operator hands over the
              first password. What changed is that it is no longer permanent, so
              say what the user can do next instead of warning that they are stuck
              with it. */}
          <div style={{marginTop:8, fontSize:12, color:"var(--text3)"}}>
            No email is sent when the account is created — give the user this first
            password directly. They can change it themselves after signing in, and
            you can email them a reset link from the table below.
          </div>
          <motion.button className="btn bp btn-sm" style={{marginTop:10}} onClick={invite} disabled={inviting} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
            {inviting ? "Creating…" : "✅ Create User"}
          </motion.button>
        </div>
      )}
      <div className="tw">
        {loading ? (
          <div style={{padding:"16px",textAlign:"center",fontSize: 13,color:"var(--text3)"}}>Loading…</div>
        ) : (
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>2FA</th><th>Last Login</th><th>Status</th><th>Password</th></tr></thead>
            <tbody>
              {users.map((u, idx) => (
                <motion.tr key={u.id} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: idx * 0.02 }}>
                  <td>{u.name||"—"}</td>
                  <td className="td2">{u.email}</td>
                  <td>{roleBadge(u.role)}</td>
                  <td><span className={`bdg ${u.mfa_enabled?"bgg":"bgr"}`}>{u.mfa_enabled?"✓ TOTP":"✗ None"}</span></td>
                  <td className="td3">{fmtLogin(u.last_login)}</td>
                  <td><span className={`bdg ${u.status==="active"?"bgg":"bgr"}`}>{u.status.toUpperCase()}</span></td>
                  <td>
                    <button
                      className="btn btn-sm"
                      disabled={resetting === u.id || mailReady === false}
                      title={mailReady === false
                        ? "SMTP is not configured on this deployment, so no reset email can be sent"
                        : `Email ${u.email} a single-use reset link`}
                      onClick={() => sendReset(u.id, u.email)}
                    >
                      {resetting === u.id ? "Sending…" : "✉️ Send reset link"}
                    </button>
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </motion.div>
    </>
  );
}

/**
 * Rotate your own password.
 *
 * The current password is required — the API enforces it, and this form does not
 * try to be cleverer than that. On success every session is signed out, this one
 * included, so the user is sent back to the login page rather than left holding
 * a token that will start returning 401 a moment later.
 */
// ---------------------------------------------------------------------------
// Two-factor authentication (TOTP). The control plane has had enrol / confirm /
// disable and a login step-up for a while; nothing in the console called them,
// so the 2FA column read "None" for everyone with no way to change it. This is
// the enrolment: secret + QR, one code to confirm, one code to disable.
// ---------------------------------------------------------------------------
function TwoFactorCard({ users, onChanged }: { users: UserRow[]; onChanged: () => void | Promise<void> }) {
  const me = getUser();
  const mine = users.find(u => me && u.email.toLowerCase() === me.email.toLowerCase());
  const enabled = mine?.mfa_enabled ?? null;

  const [enrolling, setEnrolling] = useState<{ secret: string; uri: string; qr: string } | null>(null);
  const [code, setCode]           = useState("");
  const [busy, setBusy]           = useState(false);
  const [disabling, setDisabling] = useState(false);

  async function startEnrol() {
    setBusy(true);
    try {
      const r = await api.auth.mfaEnroll();
      const QR = await import("qrcode");
      const qr = await QR.toDataURL(r.otpauth_uri, { margin: 1, width: 180, color: { dark: "#e6eaef", light: "#00000000" } });
      setEnrolling({ secret: r.secret, uri: r.otpauth_uri, qr });
      setCode("");
    } catch (e) {
      showToast(`Could not start enrolment: ${e instanceof Error ? e.message : String(e)}`, "e", "⚠️");
    } finally { setBusy(false); }
  }
  async function confirm() {
    if (!enrolling || code.trim().length < 6) return;
    setBusy(true);
    try {
      await api.auth.mfaConfirm(enrolling.secret, code.trim());
      showToast("Two-factor authentication is on. You will be asked for a code at every sign-in.", "s", "🔐");
      setEnrolling(null); setCode("");
      await onChanged();
    } catch (e) {
      showToast(`Not activated: ${e instanceof Error ? e.message : String(e)}`, "e", "⚠️");
    } finally { setBusy(false); }
  }
  async function disable() {
    if (code.trim().length < 6) return;
    setBusy(true);
    try {
      await api.auth.mfaDisable(code.trim());
      showToast("Two-factor authentication is off for your account.", "s", "🔓");
      setDisabling(false); setCode("");
      await onChanged();
    } catch (e) {
      showToast(`Not disabled: ${e instanceof Error ? e.message : String(e)}`, "e", "⚠️");
    } finally { setBusy(false); }
  }

  return (
    <motion.div className="panel" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={tweenFast}>
      <div className="ph">
        <div className="ptitle">🔐 Two-factor authentication</div>
        {enabled === null ? <span className="td3" style={{ fontSize: 12.5 }}>—</span>
          : <span className={`bdg ${enabled ? "bgg" : "ba"}`}>{enabled ? "ON · TOTP" : "OFF"}</span>}
      </div>
      <div className="pb" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <div className="td3" style={{ fontSize: 13, lineHeight: 1.5 }}>
          Time-based one-time codes from an authenticator app (Google Authenticator, Authy, 1Password, Bitwarden).
          Once on, every sign-in to this account asks for the 6-digit code after the password.
          {enabled === false && " Recommended for every account that can change WAF policy."}
        </div>

        {enabled === false && !enrolling && (
          <div><motion.button className="btn bp btn-sm" disabled={busy} onClick={startEnrol} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
            {busy ? "…" : "🔐 Turn on two-factor"}
          </motion.button></div>
        )}

        {enrolling && (
          <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: 18, alignItems: "start" }}>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={enrolling.qr} alt="TOTP enrolment QR code" width={180} height={180} style={{ border: "1px solid var(--border)", borderRadius: 6, padding: 8, background: "rgba(255,255,255,.03)" }} />
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div className="td3" style={{ fontSize: 13 }}>1. Scan the code with your authenticator app, or enter the secret by hand:</div>
              <code style={{ fontSize: 13, userSelect: "all", wordBreak: "break-all" }}>{enrolling.secret}</code>
              <div className="td3" style={{ fontSize: 13 }}>2. Enter the 6-digit code the app shows now. Nothing changes until this code is accepted.</div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <input className="fin2" inputMode="numeric" pattern="[0-9]*" maxLength={8} placeholder="123 456" value={code}
                  onChange={e => setCode(e.target.value.replace(/\s+/g, ""))} onKeyDown={e => { if (e.key === "Enter") confirm(); }} style={{ width: 140, fontFamily: "var(--font-mono)", letterSpacing: ".12em" }} />
                <motion.button className="btn bp btn-sm" disabled={busy || code.trim().length < 6} onClick={confirm} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>{busy ? "…" : "✅ Activate"}</motion.button>
                <button className="btn bg-btn btn-sm" onClick={() => { setEnrolling(null); setCode(""); }}>Cancel</button>
              </div>
            </div>
          </div>
        )}

        {enabled === true && !disabling && (
          <div><button className="btn bg-btn btn-sm" onClick={() => { setDisabling(true); setCode(""); }}>Turn off two-factor…</button></div>
        )}
        {enabled === true && disabling && (
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <span className="td3" style={{ fontSize: 13 }}>Enter a current code to turn it off:</span>
            <input className="fin2" inputMode="numeric" maxLength={8} placeholder="123 456" value={code}
              onChange={e => setCode(e.target.value.replace(/\s+/g, ""))} onKeyDown={e => { if (e.key === "Enter") disable(); }} style={{ width: 140, fontFamily: "var(--font-mono)", letterSpacing: ".12em" }} />
            <motion.button className="btn bgn btn-sm" disabled={busy || code.trim().length < 6} onClick={disable} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>{busy ? "…" : "Turn off"}</motion.button>
            <button className="btn bg-btn btn-sm" onClick={() => { setDisabling(false); setCode(""); }}>Cancel</button>
          </div>
        )}
      </div>
    </motion.div>
  );
}

function ChangePasswordCard() {
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);

  const tooShort = next.length > 0 && next.length < 12;
  const mismatch = confirm.length > 0 && next !== confirm;
  const ready = cur && next && !tooShort && !mismatch && !busy;

  async function submit() {
    if (!ready) return;
    setBusy(true);
    try {
      const res = await api.auth.changePassword(cur, next);
      showToast(res.message ?? "Password updated", "s", "🔐");
      setCur(""); setNext(""); setConfirm("");
      // Every session just died, including this tab's. Send the user to sign in
      // again instead of letting the next request fail mysteriously.
      setTimeout(() => { logout(); window.location.href = "/login"; }, 1600);
    } catch (e) {
      showToast(e instanceof Error ? e.message : "Could not change password", "e", "⚠️");
    } finally { setBusy(false); }
  }

  return (
    <motion.div className="panel" style={{ marginBottom: 14 }}
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={tweenFast}>
      <div className="ph"><div className="ptitle">🔐 Your password</div></div>
      <div className="pb">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
          <div className="fg2"><label className="flbl2">Current password *</label>
            <input className="fin2" type="password" autoComplete="current-password"
              value={cur} onChange={e => setCur(e.target.value)} /></div>
          <div className="fg2"><label className="flbl2">New password *</label>
            <input className="fin2" type="password" autoComplete="new-password"
              placeholder="min 12 characters" value={next} onChange={e => setNext(e.target.value)} /></div>
          <div className="fg2"><label className="flbl2">Confirm new password *</label>
            <input className="fin2" type="password" autoComplete="new-password"
              value={confirm} onChange={e => setConfirm(e.target.value)} /></div>
        </div>
        <div style={{ marginTop: 8, fontSize: 12, color: "var(--text3)" }}>
          {tooShort ? "Use at least 12 characters."
            : mismatch ? "Both new-password entries must match."
            : "Changing your password signs out every session, including this one."}
        </div>
        <motion.button className="btn bp btn-sm" style={{ marginTop: 10 }} onClick={submit}
          disabled={!ready} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
          {busy ? "Updating…" : "🔐 Change password"}
        </motion.button>
      </div>
    </motion.div>
  );
}

// Cluster status — 100% live from GET /cluster/health (same source as the full
// Cluster page). Degrades to an honest placeholder when the control plane is
// unreachable; nothing here is hard-coded.
function ClusterTab() {
  const [health, setHealth] = useState<ClusterHealth | null>(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function f() {
      try { const r = await api.cluster.health(); if (!cancelled) { setHealth(r); setErr(false); } }
      catch { if (!cancelled) setErr(true); }
    }
    f();
    const t = setInterval(f, 10_000);
    return () => { cancelled = true; clearInterval(t); };
  }, []);

  const cp = health?.control_plane;
  const dp = health?.data_plane;
  const cpNodes = cp?.nodes ?? [];
  const dpNodes = dp?.nodes ?? [];

  const fmtAgo = (s: number) =>
    s == null || s < 0 ? "—" : s < 60 ? `${Math.floor(s)}s ago` : s < 3600 ? `${Math.floor(s / 60)}m ago` : s < 86400 ? `${Math.floor(s / 3600)}h ago` : `${Math.floor(s / 86400)}d ago`;

  const headBadge = !health
    ? <span className="bdg bgr">{err ? "● unreachable" : "loading…"}</span>
    : cp?.enabled
      ? <span className={`bdg ${cp.write_available ? "bgg" : "br"}`}><span className="bdr" />{cp.healthy}/{cp.total} nodes</span>
      : <span className="bdg bcy">standalone</span>;

  return (
    <motion.div className="panel" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={tweenFast}>
      <div className="ph">
        <div className="ptitle">⚡ Cluster Status</div>
        {headBadge}
      </div>
      <div className="pb">
        {!health ? (
          <div style={{ padding: "26px 12px", textAlign: "center", color: "var(--text3)", fontFamily: "var(--font-mono)", fontSize: 14 }}>
            {err ? "Control plane unreachable — no live cluster data to show." : "Loading live cluster health…"}
          </div>
        ) : (
          <>
            {cp?.enabled ? (
              <div style={{ display: "grid", gridTemplateColumns: `repeat(${Math.min(Math.max(cpNodes.length, 1), 3)},1fr)`, gap: 10, marginBottom: 16 }}>
                {cpNodes.length === 0 ? (
                  <div className="srd">No control-plane nodes reporting.</div>
                ) : cpNodes.map((n, idx) => (
                  <motion.div key={n.node_id} className={`nodecard ${n.is_leader ? "leader" : ""}`} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: idx * 0.08, ...spring }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                      <div className={`sd ${n.reachable ? "g" : "r"}`} />
                      <span className="ncr" style={n.is_leader ? { background: "rgba(200,0,30,.2)", color: "var(--red-b)", border: "1px solid var(--border)" } : { background: "rgba(0,200,240,.12)", color: "var(--cyan)", border: "1px solid rgba(0,200,240,.3)" }}>{n.is_leader ? "LEADER" : n.role.toUpperCase()}</span>
                      {n.is_self && <span className="bdg bgr" style={{ marginLeft: "auto" }}>this node</span>}
                    </div>
                    <div className="ncn">node {n.node_id}</div>
                    <div className="ncs">Addr: {n.addr || "—"}</div>
                    <div className="ncs">{n.reachable ? fmtAgo(n.last_seen_sec) : "unreachable"}</div>
                  </motion.div>
                ))}
              </div>
            ) : (
              <div style={{ padding: "18px 12px", textAlign: "center", marginBottom: 14 }}>
                <div style={{ fontSize: 26, marginBottom: 6 }}>🧩</div>
                <div style={{ fontSize: 15, fontWeight: 700, color: "var(--text2)", marginBottom: 4 }}>Standalone — HA not enabled</div>
                <div className="srd">Running a single control-plane node. Add replicas for spare capacity — write leadership fails over via a Postgres advisory lock, with no quorum to maintain.</div>
              </div>
            )}

            {([
              // No quorum row: leadership is a Postgres advisory lock, so writes
              // survive on a single node and a control-plane majority is not
              // required. Reporting "quorum" would describe a constraint that no
              // longer exists.
              cp?.enabled
                ? ["Write leader", `${cp.leader_id ?? "none elected"} · ${cp.healthy}/${cp.total} nodes online`, cp.write_available ? "bgg" : "br", cp.write_available ? "✓ AVAILABLE" : "⚠ NO LEADER"]
                : ["Write leader", "Standalone — this node accepts all writes", "bcy", "N/A"],
              ["Protection", health.protection_active ? "Traffic is being inspected and enforced" : "Protection is not fully active", health.protection_active ? "bgg" : "br", health.protection_active ? "✓ ACTIVE" : "⚠ AT RISK"],
              ["Data-Plane Nodes", dpNodes.length ? dpNodes.map(n => n.id).join(", ") : "No data-plane nodes reporting", dp && dp.total > 0 && dp.healthy === dp.total ? "bgg" : dp && dp.healthy > 0 ? "ba" : "br", `${dp?.total ?? 0} node${(dp?.total ?? 0) === 1 ? "" : "s"}`],
            ] as [string, string, string, string][]).map(([t, d, cls, val]) => (
              <div key={t} className="srow">
                <div style={{ flex: 1, minWidth: 0 }}><div className="srt">{t}</div><div className="srd" style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{d}</div></div>
                <span className={`bdg ${cls}`}>{val}</span>
              </div>
            ))}

            <div style={{ marginTop: 12, fontSize: 12.5, color: "var(--text3)", fontFamily: "var(--font-mono)" }}>
              Live from <code>GET /cluster/health</code> · refreshes every 10s · full fleet view under <b>Cluster</b>.
            </div>
          </>
        )}
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
    <motion.div className="panel" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={tweenFast}>
      <div className="ph">
        <div className="ptitle">🔔 Notification Channels</div>
        <motion.button className="btn bc btn-sm" onClick={() => setAdding(a => !a)} whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
          {adding ? "✕ Cancel" : "+ Add Channel"}
        </motion.button>
      </div>
      <div className="pb">
        <div style={{ fontSize: 13, color: "var(--text3)", lineHeight: 1.7, marginBottom: 12, fontFamily: "var(--font-mono)" }}>
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
          <div style={{ padding: 24, textAlign: "center", fontSize: 13, color: "var(--text3)", fontFamily: "var(--font-mono)" }}>Loading channels…</div>
        ) : channels.length === 0 ? (
          <div style={{ padding: 24, textAlign: "center", fontSize: 13, color: "var(--text3)", fontFamily: "var(--font-mono)" }}>No channels configured. Add one to start delivering alerts to your SOC.</div>
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
    <motion.div className="panel" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={tweenFast}>
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
          {PRODUCT_NAME}&apos;s own engine — no third-party proxy. Customer-website certificates are separate and live
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

function LanguagePicker() {
  const { locale, setLocale, t } = useT();
  return (
    <div style={{ display: "grid", gap: 6 }}>
      <label style={{ fontSize: 12, color: "var(--text3)", fontFamily: "var(--font-mono)" }}>{t("common.language")}</label>
      <select className="fsel" value={locale} onChange={e => setLocale(e.target.value as Locale)} style={{ maxWidth: 260 }}>
        {SUPPORTED_LOCALES.map(l => <option key={l.code} value={l.code}>{l.label}</option>)}
      </select>
      <div style={{ fontSize: 12, color: "var(--text3)", lineHeight: 1.5 }}>{t("common.language_hint")}</div>
    </div>
  );
}
