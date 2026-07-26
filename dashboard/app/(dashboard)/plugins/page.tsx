"use client";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { api } from "@/lib/api";
import { staggerContainer, fadeUp } from "@/lib/animations";

/**
 * This page used to render a six-entry "WASM Plugin Marketplace" that did not
 * exist: invented plugins with invented authors, byte sizes and star ratings
 * (⭐ 4.9), hardcoded KPIs reading "3 installed / 14 available / 2 updates", and
 * Install / Update / Config buttons whose entire implementation was a toast.
 * The backend's handleListPlugins returns an empty array unconditionally and
 * there is no plugin table, no upload endpoint and no per-site enable path.
 *
 * A prospect clicking "Install" on a plugin that cannot exist is the kind of
 * thing that ends an evaluation, so the catalogue is gone. The WASM runtime in
 * crates/sentinel-plugins is real, which is why this page still exists and says
 * so — but it now reports the true state (no plugins loaded) and offers no
 * control that does not work.
 */
interface PluginRow {
  name?: string;
  version?: string;
  status?: string;
}

export default function PluginsPage() {
  const [plugins, setPlugins] = useState<PluginRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api.plugins
      .list()
      .then(r => { if (alive) setPlugins((r.plugins as PluginRow[]) ?? []); })
      .catch(e => { if (alive) setError(e instanceof Error ? e.message : "request failed"); });
    return () => { alive = false; };
  }, []);

  return (
    <motion.div className="sec" variants={staggerContainer} initial="hidden" animate="visible">
      <motion.div variants={fadeUp}>
        <div className="sec-title">WASM Plugins</div>
        <div className="sec-sub">
          WebAssembly plugin runtime for custom request and response processing
        </div>
      </motion.div>

      {error && (
        <motion.div variants={fadeUp} className="pc" style={{ borderColor: "var(--red)" }}>
          <div style={{ fontSize: "var(--fs-h3)", fontWeight: 600, color: "var(--red)" }}>
            Could not load plugins
          </div>
          <div style={{ fontSize: "var(--fs-sm)", color: "var(--text2)", marginTop: 6 }}>
            {error}
          </div>
        </motion.div>
      )}

      {!error && plugins === null && (
        <motion.div variants={fadeUp} className="pc">
          <div style={{ fontSize: "var(--fs-sm)", color: "var(--text3)" }}>Loading…</div>
        </motion.div>
      )}

      {!error && plugins !== null && plugins.length === 0 && (
        <motion.div variants={fadeUp} className="pc" style={{ padding: "32px 28px" }}>
          <div style={{ fontSize: "var(--fs-h2)", fontWeight: 600, color: "var(--text)" }}>
            No plugins loaded
          </div>
          <div
            style={{
              fontSize: "var(--fs-body)", color: "var(--text2)",
              marginTop: 10, maxWidth: "72ch", lineHeight: 1.6,
            }}
          >
            The data plane ships a WebAssembly plugin runtime, but no plugins are
            currently registered for this tenant and there is no upload path yet —
            plugin distribution and per-site activation are on the roadmap, not in
            this build.
          </div>
          <div
            style={{
              fontSize: "var(--fs-sm)", color: "var(--text3)",
              marginTop: 14, fontFamily: "var(--font-mono)",
            }}
          >
            Runtime: crates/sentinel-plugins · registered plugins: 0
          </div>
        </motion.div>
      )}

      {!error && plugins !== null && plugins.length > 0 && (
        <motion.div
          variants={staggerContainer}
          style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 14 }}
        >
          {plugins.map((p, i) => (
            <motion.div key={p.name ?? i} className="pc" variants={fadeUp}>
              <div className="pcn">{p.name ?? "unnamed"}</div>
              <div className="pca">{p.version ?? "—"}</div>
              {p.status && <span className="bdg bgg">{p.status.toUpperCase()}</span>}
            </motion.div>
          ))}
        </motion.div>
      )}
    </motion.div>
  );
}
