/**
 * Tells the always-mounted chrome (top-bar bell, sidebar badge) that the set of
 * open alerts changed, so their counts update the moment an operator acts.
 *
 * The bell used to fetch its count once, when the console first loaded. The top
 * bar is never unmounted while you move between pages, so closing alerts on the
 * Alerts page left the badge showing the old number until a full reload.
 */
export const ALERTS_CHANGED = "sk:alerts-changed";

export function announceAlertsChanged(): void {
  if (typeof window !== "undefined") window.dispatchEvent(new Event(ALERTS_CHANGED));
}

/** Run `refresh` on every announcement; returns the unsubscribe function. */
export function onAlertsChanged(refresh: () => void): () => void {
  if (typeof window === "undefined") return () => {};
  window.addEventListener(ALERTS_CHANGED, refresh);
  return () => window.removeEventListener(ALERTS_CHANGED, refresh);
}
