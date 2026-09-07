"use client";
import { useEffect } from "react";
import { isChunkFailure } from "@/lib/chunkFailure";

/**
 * Recover a tab whose JavaScript no longer exists on the server.
 *
 * Rolling the dashboard replaces the container, and `generateBuildId` mints a
 * fresh build id on every start, so the chunk filenames change. A tab that was
 * already open keeps asking for the old ones, gets 404s, and stops working —
 * buttons do nothing, navigation dies. It reads exactly like being locked out,
 * and on 2026-09-07 an operator spent an hour on that after three dashboard
 * rolls in two hours, reasonably concluding the WAF had blocked them.
 *
 * A stale tab cannot be repaired in place: the code it needs is gone. The only
 * honest recovery is to reload once against the new build. This listens for the
 * two ways the failure surfaces — a rejected dynamic import and a failed script
 * element — and reloads, guarding with sessionStorage so a genuinely broken
 * build cannot put the tab in a reload loop.
 *
 * Deliberately narrow. It matches only chunk-loading failures, so an ordinary
 * application error still surfaces as an error instead of being papered over by
 * a page refresh, which would hide real bugs.
 */
const GUARD_KEY = "sentinel.chunk-reload-at";
const GUARD_WINDOW_MS = 30_000;


function reloadOnce(): void {
  try {
    const last = Number(sessionStorage.getItem(GUARD_KEY) ?? 0);
    if (Date.now() - last < GUARD_WINDOW_MS) return; // already tried; do not loop
    sessionStorage.setItem(GUARD_KEY, String(Date.now()));
  } catch {
    // Private mode with storage blocked: one reload is still better than a dead
    // tab, and without the guard the worst case is a visible reload loop the
    // operator can escape by closing the tab.
  }
  window.location.reload();
}

export default function ChunkRecovery() {
  useEffect(() => {
    const onError = (e: ErrorEvent) => {
      if (isChunkFailure(String(e.message ?? ""))) reloadOnce();
    };
    const onRejection = (e: PromiseRejectionEvent) => {
      const r = e.reason as { message?: string; name?: string } | undefined;
      if (isChunkFailure(`${r?.name ?? ""} ${r?.message ?? ""}`)) reloadOnce();
    };
    window.addEventListener("error", onError);
    window.addEventListener("unhandledrejection", onRejection);
    return () => {
      window.removeEventListener("error", onError);
      window.removeEventListener("unhandledrejection", onRejection);
    };
  }, []);
  return null;
}
