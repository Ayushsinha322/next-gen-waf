"use client";
// Localisation seed.
//
// English is the only dictionary today and that is fine for the first
// customers. What this wires in NOW is the plumbing — a provider, a `useT` hook
// and a flat key → string dictionary with {var} interpolation — so that the
// second language is a dictionary file, not a migration of twenty pages of
// literals. New strings should go through t(); existing pages are converted as
// they are touched (sidebar + top bar first).
//
// No machine-translated placeholder locales: a language is listed only when a
// person has written its dictionary.
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

export type Locale = "en";
export const SUPPORTED_LOCALES: Array<{ code: Locale; label: string }> = [{ code: "en", label: "English" }];
export const DEFAULT_LOCALE: Locale = "en";
const STORAGE_KEY = "sentinel-locale";

type Dict = Record<string, string>;

export const en: Dict = {
  // navigation
  "nav.group.monitor": "Monitor",
  "nav.group.protect": "Protect",
  "nav.group.intelligence": "Intelligence",
  "nav.group.system": "System",
  "nav.overview": "Overview",
  "nav.traffic": "Traffic",
  "nav.alerts": "Alerts",
  "nav.logs": "Logs",
  "nav.events": "Threat Search",
  "nav.reports": "Reports",
  "nav.sites": "Sites",
  "nav.rules": "Rules",
  "nav.certificates": "Certificates",
  "nav.blocked": "Blocked Sources",
  "nav.plugins": "Plugins",
  "nav.threat-intel": "Threat Intel",
  "nav.ml": "ML Engine",
  "nav.cluster": "Cluster",
  "nav.audit": "Audit Log",
  "nav.jobs": "System Jobs",
  "nav.global-settings": "Global Settings",
  "nav.settings": "Settings",
  "nav.live": "live",
  // cluster footer
  "cluster.connecting": "connecting…",
  "cluster.unreachable": "control plane unreachable",
  "cluster.no_leader": "no leader elected",
  "cluster.leader": "{id} · leader",
  "cluster.online": "{healthy}/{total} online",
  "cluster.standalone": "Standalone",
  "cluster.nodes": "{n} WAF node",
  "cluster.nodes_plural": "{n} WAF nodes",
  // common
  "common.refresh": "Refresh",
  "common.loading": "Loading…",
  "common.save": "Save",
  "common.cancel": "Cancel",
  "common.delete": "Delete",
  "common.search": "Search",
  "common.language": "Language",
  "common.language_hint": "Only English has a dictionary today. Further languages can be added without changing any screen.",
};

const DICTS: Record<Locale, Dict> = { en };

export function translate(locale: Locale, key: string, vars?: Record<string, string | number>): string {
  const s = DICTS[locale]?.[key] ?? DICTS[DEFAULT_LOCALE][key] ?? key;
  if (!vars) return s;
  return s.replace(/\{(\w+)\}/g, (_, k: string) => (k in vars ? String(vars[k]) : `{${k}}`));
}

interface I18nCtx { locale: Locale; setLocale: (l: Locale) => void; t: (key: string, vars?: Record<string, string | number>) => string }
const Ctx = createContext<I18nCtx>({ locale: DEFAULT_LOCALE, setLocale: () => {}, t: (k, v) => translate(DEFAULT_LOCALE, k, v) });

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(DEFAULT_LOCALE);
  useEffect(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved && SUPPORTED_LOCALES.some(l => l.code === saved)) setLocaleState(saved as Locale);
    } catch { /* ignore */ }
  }, []);
  const setLocale = useCallback((l: Locale) => {
    setLocaleState(l);
    try { localStorage.setItem(STORAGE_KEY, l); } catch { /* ignore */ }
    if (typeof document !== "undefined") document.documentElement.lang = l;
  }, []);
  const t = useCallback((key: string, vars?: Record<string, string | number>) => translate(locale, key, vars), [locale]);
  const value = useMemo(() => ({ locale, setLocale, t }), [locale, setLocale, t]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useT() { return useContext(Ctx); }
