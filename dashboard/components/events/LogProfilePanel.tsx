"use client";
/**
 * Log Profiles — saved, named log views scoped to one web application.
 *
 * The support call this exists for: "this is <customer>, send me the WAF logs
 * for my app for 3 August." Without a profile the operator rebuilds the filter
 * set from memory under time pressure, and two operators handling the same
 * customer produce different files. A profile makes that view a named artifact:
 * pick the customer, pick the date, download.
 *
 * The profile stores WHICH events (site + filters). The date is always supplied
 * per request, because it is the one thing that differs on every call.
 */
import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { showToast } from "@/components/ui/Toast";
import { api, type LogProfile, type LogProfileInput, type ExportFormat, type Site } from "@/lib/api";

/** The filter set a profile captures, shared with the Threat Search page. */
export interface ProfileFilters {
  site: string; rule: string; action: string; ip: string;
  country: string; protocol: string; severity: string; q: string;
}

const FORMATS: { id: ExportFormat; label: string; hint: string }[] = [
  { id: "csv",    label: "CSV",    hint: "Opens in Excel — what most customers expect" },
  { id: "ndjson", label: "NDJSON", hint: "One JSON object per line — for a customer's SIEM" },
  { id: "json",   label: "JSON",   hint: "Single JSON document" },
];

export default function LogProfilePanel({
  profiles, sites, activeId, filters, from, to, busy,
  onLoad, onChanged, onExporting,
}: {
  profiles: LogProfile[];
  sites: Site[];
  activeId: string;
  filters: ProfileFilters;
  /** Currently selected window, unix seconds — whatever the page's date controls say. */
  from: number;
  to: number;
  busy: boolean;
  onLoad: (p: LogProfile | null) => void;
  onChanged: () => void;
  onExporting: (v: boolean) => void;
}) {
  const [editing, setEditing] = useState<LogProfile | "new" | null>(null);
  const [format, setFormat] = useState<ExportFormat>("csv");
  const [exporting, setExporting] = useState(false);

  const active = profiles.find(p => p.id === activeId) ?? null;

  async function runExport() {
    setExporting(true);
    onExporting(true);
    try {
      // A saved profile exports through its own endpoint so the audit trail
      // records WHICH customer view was handed over, not just a filter soup.
      const r = active
        ? await api.logProfiles.exportDownload(active.id, from, to, format)
        : await api.events.exportDownload({ ...filters, from, to }, format);
      showToast(
        r.rows === 0
          ? `No events in that window — ${r.filename} is empty`
          : `${r.rows.toLocaleString()} events → ${r.filename}`,
        r.rows === 0 ? "i" : "s");
    } catch (e) {
      // The server refuses an oversized export rather than silently truncating,
      // and that message carries the real row count — surface it verbatim.
      showToast(e instanceof Error ? e.message : "Export failed", "e");
    } finally {
      setExporting(false);
      onExporting(false);
    }
  }

  async function remove(p: LogProfile) {
    if (!window.confirm(`Delete the log profile "${p.name}"? This does not delete any logs.`)) return;
    try {
      await api.logProfiles.remove(p.id);
      showToast(`Profile "${p.name}" deleted`, "s");
      if (p.id === activeId) onLoad(null);
      onChanged();
    } catch (e) {
      showToast(e instanceof Error ? e.message : "Delete failed", "e");
    }
  }

  return (
    <>
      <div className="panel">
        <div className="ph">
          <div className="ptitle">Log Profiles</div>
          <span className="panel-badge">
            {profiles.length === 0 ? "none saved" : `${profiles.length} saved`}
          </span>
        </div>
        <div className="pb" style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <select
            className="fsel"
            style={{ minWidth: 230 }}
            value={activeId}
            onChange={e => onLoad(profiles.find(p => p.id === e.target.value) ?? null)}
            title="Load a saved view for one application"
          >
            <option value="">— Ad-hoc view (no profile) —</option>
            {profiles.map(p => (
              <option key={p.id} value={p.id}>
                {p.name}{p.site ? ` · ${p.site}` : " · all sites"}
              </option>
            ))}
          </select>

          <button className="btn bg-btn btn-sm" onClick={() => setEditing("new")}>
            + Save current view
          </button>
          {active && (
            <>
              <button className="btn bg-btn btn-sm" onClick={() => setEditing(active)}>Edit</button>
              <button className="btn bg-btn btn-sm" onClick={() => remove(active)}>Delete</button>
            </>
          )}

          <div style={{ flex: 1 }} />

          <select
            className="fsel"
            value={format}
            onChange={e => setFormat(e.target.value as ExportFormat)}
            title={FORMATS.find(f => f.id === format)?.hint}
          >
            {FORMATS.map(f => <option key={f.id} value={f.id}>{f.label}</option>)}
          </select>
          <motion.button
            className="btn bc btn-sm"
            onClick={runExport}
            disabled={exporting || busy}
            whileHover={{ scale: exporting ? 1 : 1.03 }}
            whileTap={{ scale: 0.97 }}
            title="Download every event in the selected window — not just the rows shown below"
          >
            {exporting ? "Preparing…" : "Download logs"}
          </motion.button>
        </div>

        {active?.description && (
          <div className="pb" style={{ paddingTop: 0, fontSize: 13, color: "var(--text3)" }}>
            {active.description}
          </div>
        )}

        <div className="pb" style={{ paddingTop: 0, fontSize: 12, color: "var(--text3)", fontFamily: "var(--font-mono)" }}>
          The download streams every matching event in the window from the event
          store — the table below is only a preview.
        </div>
      </div>

      <AnimatePresence>
        {editing && (
          <ProfileEditor
            key="editor"
            profile={editing === "new" ? null : editing}
            sites={sites}
            filters={filters}
            windowSecs={Math.max(1, to - from)}
            defaultFormat={format}
            onClose={() => setEditing(null)}
            onSaved={() => { setEditing(null); onChanged(); }}
          />
        )}
      </AnimatePresence>
    </>
  );
}

/** Create/edit dialog. Seeded from the filters currently on screen, so the
 *  operator builds the view by searching, then names it. */
function ProfileEditor({
  profile, sites, filters, windowSecs, defaultFormat, onClose, onSaved,
}: {
  profile: LogProfile | null;
  sites: Site[];
  filters: ProfileFilters;
  windowSecs: number;
  defaultFormat: ExportFormat;
  onClose: () => void;
  onSaved: () => void;
}) {
  const seed: LogProfileInput = profile
    ? {
        name: profile.name, description: profile.description, site: profile.site,
        rule: profile.rule, action: profile.action, ip: profile.ip,
        country: profile.country, protocol: profile.protocol, severity: profile.severity,
        q: profile.q, default_range_secs: profile.default_range_secs,
        default_format: profile.default_format,
      }
    : {
        name: "", description: "", ...filters,
        default_range_secs: windowSecs, default_format: defaultFormat,
      };

  const [form, setForm] = useState<LogProfileInput>(seed);
  const [saving, setSaving] = useState(false);

  // Site names as the data plane writes them into the event store. A profile
  // may also point at an application whose site row was since renamed, so the
  // stored value is kept as an option even when it is no longer in the list.
  const siteOptions = Array.from(new Set([
    ...sites.map(s => s.name),
    ...(form.site ? [form.site] : []),
  ].filter(Boolean))).sort();

  function set<K extends keyof LogProfileInput>(k: K, v: LogProfileInput[K]) {
    setForm(f => ({ ...f, [k]: v }));
  }

  async function save() {
    if (!form.name.trim()) { showToast("Give the profile a name", "e"); return; }
    setSaving(true);
    try {
      if (profile) await api.logProfiles.update(profile.id, form);
      else await api.logProfiles.create(form);
      showToast(`Profile "${form.name}" saved`, "s");
      onSaved();
    } catch (e) {
      showToast(e instanceof Error ? e.message : "Save failed", "e");
    } finally {
      setSaving(false);
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      onClick={onClose}
      style={{
        position: "fixed", inset: 0, background: "rgba(0,0,0,.6)", zIndex: 200,
        display: "flex", alignItems: "center", justifyContent: "center", padding: 20,
      }}
    >
      <motion.div
        className="panel"
        initial={{ y: 12, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 12, opacity: 0 }}
        onClick={e => e.stopPropagation()}
        style={{ width: "min(620px, 100%)", maxHeight: "88vh", overflow: "auto" }}
      >
        <div className="ph">
          <div className="ptitle">{profile ? "Edit log profile" : "Save current view as a profile"}</div>
        </div>
        <div className="pb" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <Field label="Profile name" hint="What you'll look for when the customer calls">
            <input className="fi2" value={form.name} autoFocus
              placeholder="e.g. Acme Portal — blocked requests"
              onChange={e => set("name", e.target.value)} />
          </Field>

          <Field label="Description" hint="Optional — context for whoever picks up the next call">
            <input className="fi2" value={form.description ?? ""}
              placeholder="e.g. Contact: soc@acme.example. Wants CSV monthly."
              onChange={e => set("description", e.target.value)} />
          </Field>

          <Field label="Web application" hint="Which app's logs this profile pulls. Leave blank for all.">
            <select className="fsel" style={{ width: "100%" }} value={form.site ?? ""}
              onChange={e => set("site", e.target.value)}>
              <option value="">All applications</option>
              {siteOptions.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </Field>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <Field label="Action"><select className="fsel" style={{ width: "100%" }} value={form.action ?? ""}
              onChange={e => set("action", e.target.value)}>
              <option value="">Any</option><option value="BLOCK">BLOCK</option><option value="DETECT">DETECT</option>
            </select></Field>
            <Field label="Severity"><select className="fsel" style={{ width: "100%" }} value={form.severity ?? ""}
              onChange={e => set("severity", e.target.value)}>
              <option value="">Any</option>
              {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map(s => <option key={s} value={s}>{s}</option>)}
            </select></Field>
            <Field label="Rule"><input className="fi2" value={form.rule ?? ""} placeholder="any"
              onChange={e => set("rule", e.target.value)} /></Field>
            <Field label="Source IP"><input className="fi2" value={form.ip ?? ""} placeholder="any"
              onChange={e => set("ip", e.target.value)} /></Field>
            <Field label="Protocol"><select className="fsel" style={{ width: "100%" }} value={form.protocol ?? ""}
              onChange={e => set("protocol", e.target.value)}>
              <option value="">Any</option><option value="h1">HTTP/1.x</option>
              <option value="h2">HTTP/2</option><option value="h3">HTTP/3</option>
            </select></Field>
            <Field label="Country"><input className="fi2" value={form.country ?? ""} placeholder="any (ISO code)"
              onChange={e => set("country", e.target.value)} /></Field>
          </div>

          <Field label="Text match" hint="Substring across path, attack and rule">
            <input className="fi2" value={form.q ?? ""} placeholder="any"
              onChange={e => set("q", e.target.value)} />
          </Field>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <Field label="Default window" hint="Pre-selected when the profile is opened">
              <select className="fsel" style={{ width: "100%" }} value={form.default_range_secs ?? 86400}
                onChange={e => set("default_range_secs", Number(e.target.value))}>
                <option value={3600}>Last 1 hour</option>
                <option value={86400}>Last 24 hours</option>
                <option value={604800}>Last 7 days</option>
                <option value={2592000}>Last 30 days</option>
              </select>
            </Field>
            <Field label="Default format" hint="What this customer usually receives">
              <select className="fsel" style={{ width: "100%" }} value={form.default_format ?? "csv"}
                onChange={e => set("default_format", e.target.value as ExportFormat)}>
                {FORMATS.map(f => <option key={f.id} value={f.id}>{f.label}</option>)}
              </select>
            </Field>
          </div>

          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 4 }}>
            <button className="btn bg-btn btn-sm" onClick={onClose}>Cancel</button>
            <button className="btn bc btn-sm" onClick={save} disabled={saving}>
              {saving ? "Saving…" : profile ? "Save changes" : "Create profile"}
            </button>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="fg2">
      <label className="flbl2">{label}</label>
      {children}
      {hint && <div style={{ fontSize: 12, color: "var(--text3)", marginTop: 3 }}>{hint}</div>}
    </div>
  );
}
