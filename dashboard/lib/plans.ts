/**
 * Presentational plan catalogue for the Home dashboard. This is intentionally
 * NOT a hard entitlement gate yet — it renders the Basic vs Pro comparison and
 * marks the active plan. Real feature-locking will be wired to a control-plane
 * entitlements concept later.
 */
export type PlanKey = "basic" | "pro";

export interface Plan {
  key:       PlanKey;
  name:      string;
  tagline:   string;
  price:     string;
  accent:    string;          // CSS color
  highlights: string[];
  limits: {
    sites:     string;
    rps:       string;
    retention: string;
    nodes:     string;
  };
}

export const PLANS: Record<PlanKey, Plan> = {
  basic: {
    key: "basic",
    name: "Basic",
    tagline: "Single-node protection for one or a few apps.",
    price: "Included",
    accent: "var(--text2)",
    highlights: [
      "OWASP CRS + core WAF rules",
      "Rate limiting & anti-DDoS",
      "Manual & ACME TLS certificates",
      "Learning → Blocking workflow",
    ],
    limits: { sites: "Up to 5 sites", rps: "Standard throughput", retention: "7-day logs", nodes: "1 node" },
  },
  pro: {
    key: "pro",
    name: "Pro",
    tagline: "Production-grade, clustered, ML-powered defense.",
    price: "Enterprise",
    accent: "var(--cyan)",
    highlights: [
      "Everything in Basic, plus:",
      "ML anomaly engine + AI Copilot",
      "Multi-node Raft cluster & HA",
      "JA4 bot fingerprinting + GeoIP",
      "Virtual patching & API discovery",
      "Unlimited sites · priority support",
    ],
    limits: { sites: "Unlimited sites", rps: "High throughput", retention: "90-day logs", nodes: "Multi-node cluster" },
  },
};

/** The plan this deployment runs as (presentational). Production ships as Pro. */
export const ACTIVE_PLAN: PlanKey = "pro";
