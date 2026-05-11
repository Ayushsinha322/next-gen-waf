/**
 * Thin typed client for the Sentinel control-plane REST API.
 * All paths are relative so Next.js rewrites proxy them in dev.
 */

const BASE = "/api/v1";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`API ${path}: ${res.status} ${text}`);
  }
  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Types (mirrors control-plane REST API)
// ---------------------------------------------------------------------------

export interface NodeStatus {
  node_id: string;
  version: string;
  uptime_s: number;
  requests_total: number;
  requests_blocked: number;
  latency_p99_ms: number;
}

export interface Site {
  id: string;
  domains: string[];
  waf_mode: "off" | "learning" | "blocking";
}

export interface TrafficPoint {
  ts: string;
  rps: number;
  blocked_rps: number;
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

export const api = {
  nodes: {
    list: () => apiFetch<NodeStatus[]>("/nodes"),
  },
  sites: {
    list: () => apiFetch<Site[]>("/sites"),
    get: (id: string) => apiFetch<Site>(`/sites/${id}`),
  },
  traffic: {
    recent: (siteId?: string) =>
      apiFetch<TrafficPoint[]>(
        siteId ? `/traffic?site=${siteId}` : "/traffic"
      ),
  },
};
