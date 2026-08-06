"use client";
/**
 * Configuration history and rollback.
 *
 * The control plane has been snapshotting every site mutation into
 * config_versions and exposing GET /config/versions and
 * POST /config/versions/:id/rollback for some time, with no client ever calling
 * either — the storage cost was already being paid for a feature no operator
 * could reach. "What happens when a config change breaks production" is the
 * first question an enterprise evaluation asks, and until now the honest answer
 * was "restore the database".
 *
 * Rollback is not a clean time machine and the dialog says so rather than
 * discovering it afterwards: sites created after a snapshot are left alone, and
 * sites deleted since are not re-created. The handler returns exactly which
 * ones it skipped, and we surface that verbatim.
 */
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { api, type ConfigVersionSummary } from "@/lib/api";
import { showToast } from "@/components/ui/Toast";

function when(iso: string) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

export default function ConfigHistory({ onClose, onRestored }: { onClose: () => void; onRestored?: () => void }) {
  const [versions, setVersions] = useState<ConfigVersionSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<ConfigVersionSummary | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    api.config.versions(50)
      .then(r => { if (alive) setVersions(r.versions ?? []); })
      .catch(e => { if (alive) setError(e instanceof Error ? e.message : "request failed"); });
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function restore(v: ConfigVersionSummary) {
    setBusy(true);
    try {
      const r = await api.config.rollback(v.id);
      const skipped = r.skipped?.length
        ? ` · ${r.skipped.length} skipped: ${r.skipped.join(", ")}`
        : "";
      showToast(`Restored ${r.restored_sites} site(s)${skipped}`, "s", "✓");
      setConfirming(null);
      onRestored?.();
      onClose();
    } catch (e) {
      showToast(e instanceof Error ? e.message : "Rollback failed", "e", "⚠️");
    } finally {
      setBusy(false);
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }}
      onClick={onClose}
      style={{
        position: "fixed", inset: 0, zIndex: 1000, background: "rgba(2,6,14,.82)",
        display: "flex", alignItems: "center", justifyContent: "center", padding: 24,
      }}
    >
      <motion.div
        role="dialog" aria-modal="true" aria-label="Configuration history"
        initial={{ y: 12, opacity: 0 }} animate={{ y: 0, opacity: 1 }}
        onClick={e => e.stopPropagation()}
        style={{
          width: "min(760px, 96vw)", maxHeight: "86vh", display: "flex", flexDirection: "column",
          background: "var(--bg2)", border: "1px solid var(--border2)", borderRadius: "var(--r)",
          boxShadow: "0 24px 64px rgba(0,0,0,.5)",
        }}
      >
        <header style={{ padding: "16px 20px", borderBottom: "1px solid var(--border2)", display: "flex", alignItems: "flex-start", gap: 12 }}>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: "var(--fs-h2)", fontWeight: 600, color: "var(--text)" }}>Configuration history</div>
            <div style={{ fontSize: "var(--fs-sm)", color: "var(--text2)", marginTop: 3 }}>
              A snapshot is taken before every site change. Restore one to undo a bad edit.
            </div>
          </div>
          <button className="btn bg-btn btn-sm" onClick={onClose} aria-label="Close">✕</button>
        </header>

        <div style={{ flex: 1, overflowY: "auto", padding: "8px 20px 20px" }}>
          {error && (
            <div style={{ padding: "14px 0", fontSize: "var(--fs-sm)", color: "var(--red)" }}>
              Could not load history — {error}
            </div>
          )}
          {!error && versions === null && (
            <div style={{ padding: "14px 0", fontSize: "var(--fs-sm)", color: "var(--text3)" }}>Loading…</div>
          )}
          {!error && versions?.length === 0 && (
            <div style={{ padding: "22px 0", fontSize: "var(--fs-sm)", color: "var(--text3)" }}>
              No snapshots yet. One is written before the next site change.
            </div>
          )}
          {!error && versions && versions.length > 0 && (
            <table style={{ width: "100%" }}>
              <thead>
                <tr>
                  <th>When</th><th>Change</th><th>Sites</th><th>By</th><th aria-label="action" />
                </tr>
              </thead>
              <tbody>
                {versions.map(v => (
                  <tr key={v.id}>
                    <td className="td3" style={{ whiteSpace: "nowrap", fontFamily: "var(--font-mono)" }}>{when(v.created_at)}</td>
                    <td className="td2" style={{ fontFamily: "var(--font-mono)" }}>{v.reason || "—"}</td>
                    <td className="td3">{v.site_count}</td>
                    <td className="td3" style={{ fontFamily: "var(--font-mono)" }}>{v.created_by ?? "—"}</td>
                    <td style={{ textAlign: "right" }}>
                      <button className="btn bg-btn btn-xs" onClick={() => setConfirming(v)}>Restore</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {confirming && (
            <div style={{
              marginTop: 16, padding: "14px 16px", borderRadius: "var(--r2)",
              background: "var(--bg3)", border: "1px solid var(--amber)",
            }}>
              <div style={{ fontSize: "var(--fs-h3)", fontWeight: 600, color: "var(--text)" }}>
                Restore the snapshot from {when(confirming.created_at)}?
              </div>
              <div style={{ fontSize: "var(--fs-sm)", color: "var(--text2)", marginTop: 8, lineHeight: 1.6 }}>
                This rewrites live protection settings for {confirming.site_count} site(s)
                and takes effect on the next config sync. Sites created after this
                snapshot are left unchanged, and sites deleted since will not be
                re-created — the result will list anything it had to skip.
              </div>
              <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
                <button className="btn bp btn-sm" disabled={busy} onClick={() => restore(confirming)}>
                  {busy ? "Restoring…" : "Restore this configuration"}
                </button>
                <button className="btn bg-btn btn-sm" disabled={busy} onClick={() => setConfirming(null)}>Cancel</button>
              </div>
            </div>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
}
