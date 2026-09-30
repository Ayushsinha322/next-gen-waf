import { describe, it, expect } from "vitest";
import { emptyForm, formToPayload, siteToForm, type SiteForm } from "../siteConfig";
import type { Site } from "../api";

/**
 * These tests pin the exact JSON contract the site-deployment wizard emits for
 * the API-security / detection features. The control-plane forwards these
 * sub-objects to the Rust data plane VERBATIM (attachRawObject), so the serde
 * field names below must match crates/sentinel-core/src/config/mod.rs exactly —
 * a rename there without a matching change here silently disables the feature.
 */

function enabledForm(): SiteForm {
  return {
    ...emptyForm(),
    name: "api-site",
    domains: ["api.example.com"],
    // JWT / OAuth2
    jwt_enabled: true, jwt_required: true, jwt_issuer: "https://auth.example.com/",
    jwt_audience: "api://svc", jwt_algorithms: ["RS256", "ES256"],
    jwt_jwks_url: "https://auth.example.com/jwks.json",
    jwt_required_scopes: ["read:orders"], jwt_scope_claim: "scp",
    // GraphQL
    graphql_enabled: true, graphql_max_depth: 8, graphql_max_complexity: 500,
    graphql_block_introspection: true,
    // gRPC
    grpc_enabled: true, grpc_max_message_kb: 2048, grpc_max_frames: 256,
    grpc_block_reflection: true, grpc_allowed_methods: ["/o.Svc/Get"], grpc_blocked_methods: [],
    // DLP
    dlp_enabled: true, dlp_action: "mask", dlp_patterns: ["\\bTOP-SECRET\\b"],
    // Fusion
    fusion_enabled: true,
    fusion_weights: { rules: 1.5, ml: 2, bot: 1, threat_intel: 1 },
    fusion_block_thresholds: [7, 5, 4, 3], fusion_limit_thresholds: [4, 3, 2, 2],
    fusion_limit_status: 429,
    // ML models + feeds
    ml_enabled: true, ml_models: ["isolation_forest"],
    ip_feeds: [{ url: "https://feed.example/level1.netset", interval: "2h", format: "cidr" }],
  };
}

describe("formToPayload — API security & detection serde keys", () => {
  const wp = formToPayload(enabledForm()).waf_policy as Record<string, any>;

  it("emits jwt with the exact Rust field names", () => {
    expect(wp.jwt).toMatchObject({
      enable: true, required: true, issuer: "https://auth.example.com/",
      audience: "api://svc", algorithms: ["RS256", "ES256"],
      jwks_url: "https://auth.example.com/jwks.json",
      required_scopes: ["read:orders"], scope_claim: "scp",
    });
  });

  it("emits graphql depth/complexity/introspection", () => {
    expect(wp.graphql).toEqual({
      enable: true, max_depth: 8, max_complexity: 500, block_introspection: true,
    });
  });

  it("converts gRPC max message KB → bytes and passes method lists", () => {
    expect(wp.grpc).toMatchObject({
      enable: true, max_message_bytes: 2048 * 1024, max_frames: 256,
      block_reflection: true, allowed_methods: ["/o.Svc/Get"], blocked_methods: [],
    });
  });

  it("emits dlp action + extra patterns", () => {
    expect(wp.dlp).toEqual({ enable: true, action: "mask", patterns: ["\\bTOP-SECRET\\b"] });
  });

  it("emits fusion, dropping neutral (1.0) weights", () => {
    expect(wp.fusion.enable).toBe(true);
    expect(wp.fusion.weights).toEqual({ rules: 1.5, ml: 2 }); // bot/threat_intel = 1 dropped
    expect(wp.fusion.block_thresholds).toEqual([7, 5, 4, 3]);
    expect(wp.fusion.limit_status).toBe(429);
  });

  it("emits ml.models and ip_reputation.feeds", () => {
    expect(wp.ml).toMatchObject({ enable: true, models: ["isolation_forest"] });
    expect(wp.ip_reputation.feeds).toEqual([
      { url: "https://feed.example/level1.netset", interval: "2h", format: "cidr" },
    ]);
  });

  it("omits every feature block when disabled", () => {
    const wp2 = formToPayload(emptyForm()).waf_policy as Record<string, any>;
    for (const k of ["jwt", "graphql", "grpc", "dlp", "fusion"]) expect(wp2[k]).toBeUndefined();
  });
});

describe("siteToForm — round-trips the new features for editing", () => {
  it("restores every feature from a stored waf_policy", () => {
    const payload = formToPayload(enabledForm());
    const site = { name: payload.name, domains: payload.domains, upstream: payload.upstream, waf_policy: payload.waf_policy } as unknown as Site;
    const f = siteToForm(site);
    expect(f.jwt_enabled).toBe(true);
    expect(f.jwt_jwks_url).toBe("https://auth.example.com/jwks.json");
    expect(f.graphql_enabled).toBe(true);
    expect(f.graphql_max_depth).toBe(8);
    expect(f.grpc_enabled).toBe(true);
    expect(f.grpc_max_message_kb).toBe(2048); // bytes → KB round-trip
    expect(f.dlp_enabled).toBe(true);
    expect(f.dlp_action).toBe("mask");
    expect(f.fusion_enabled).toBe(true);
    expect(f.fusion_weights.rules).toBe(1.5);
    expect(f.ip_feeds).toHaveLength(1);
    expect(f.ip_feeds[0].interval).toBe("2h");
  });
});

/**
 * Per-path policy overrides, and the round-trip that guards against silent
 * data loss.
 *
 * The first version of this feature shipped with siteToForm not reading
 * path_overrides back. Because formToPayload emits a WHOLE waf_policy and the
 * server replaces it, loading a site and saving it for any unrelated reason —
 * flipping the mode, editing a domain — silently DELETED the operator's per-path
 * policy. It was found on the deploy VM after a mode change wiped four live
 * overrides, not by a test, which is why the round-trip is pinned here now.
 */
describe("path overrides", () => {
  function siteWithOverrides(): Site {
    return {
      id: "s1", tenant_id: "t1", name: "juice", domains: ["localhost"],
      upstream: { load_balancer: "round_robin", servers: [{ host: "app", port: 3000, weight: 1, tls: false }] },
      waf_policy: {
        mode: "learning", paranoia_level: 2, anomaly_threshold: 10,
        path_overrides: [
          { path_prefix: "/assets/", mode: "off" },
          { path_prefix: "/legacy/", mode: "learning" },
          { path_prefix: "/rest/", anomaly_threshold: 3 },
          { path_prefix: "/rest/admin/", anomaly_threshold: 2 },
        ],
      },
      status: "active", created_at: "", updated_at: "",
    } as unknown as Site;
  }

  it("survives a load/save round-trip", () => {
    const out = formToPayload(siteToForm(siteWithOverrides()));
    const ov = (out.waf_policy as Record<string, unknown>).path_overrides as Record<string, unknown>[];
    expect(ov, "path_overrides must not be dropped by a round-trip").toHaveLength(4);
    expect(ov.map(o => o.path_prefix)).toEqual(["/assets/", "/legacy/", "/rest/", "/rest/admin/"]);
    expect(ov[0].mode).toBe("off");
    expect(ov[3].anomaly_threshold).toBe(2);
    // An override that only sets a threshold must not gain a bogus mode.
    expect(ov[2].mode).toBeUndefined();
    // ...and one that only sets a mode must not gain a bogus threshold.
    expect(ov[0].anomaly_threshold).toBeUndefined();
  });

  it("drops rows that would have no effect, and keeps the key present", () => {
    const f = siteToForm(siteWithOverrides());
    f.path_overrides = [
      { path_prefix: "/a/", mode: "off", anomaly_threshold: "" },
      { path_prefix: "", mode: "off", anomaly_threshold: "" },          // no prefix
      { path_prefix: "/b/", mode: "", anomaly_threshold: "" },          // sets nothing
      { path_prefix: "  /c/  ", mode: "", anomaly_threshold: 4 },       // trimmed
    ];
    const ov = (formToPayload(f).waf_policy as Record<string, unknown>).path_overrides as Record<string, unknown>[];
    expect(ov.map(o => o.path_prefix)).toEqual(["/a/", "/c/"]);
  });

  it("emits the key even when empty, so clearing is expressible", () => {
    const f = siteToForm(siteWithOverrides());
    f.path_overrides = [];
    const waf = formToPayload(f).waf_policy as Record<string, unknown>;
    expect("path_overrides" in waf, "an absent key makes 'cleared' indistinguishable from 'forgotten'").toBe(true);
    expect(waf.path_overrides).toEqual([]);
  });

  it("a site with no overrides round-trips to an empty list, not undefined", () => {
    const site = siteWithOverrides();
    delete (site.waf_policy as Record<string, unknown>).path_overrides;
    const f = siteToForm(site);
    expect(f.path_overrides).toEqual([]);
  });
});

describe("a console save keeps the policy keys the console does not manage", () => {
  // The server replaces waf_policy wholesale, and the form used to rebuild it
  // from its own fields only — so saving a site erased crs_policy (set through
  // the API) and anything else an API client had stored. (Code review.)
  const stored = (waf_policy: Record<string, unknown>): Site =>
    ({ id: "s1", name: "site", domains: ["app.example"], upstream: {}, waf_policy } as unknown as Site);

  it("carries crs_policy and unknown keys through load and save", () => {
    const site = stored({
      mode: "learning", paranoia_level: 2, anomaly_threshold: 10,
      crs_policy: { outbound_anomaly_score_threshold: "8", max_num_args: "400" },
      some_future_key: { a: 1 },
    });
    const out = formToPayload(siteToForm(site)).waf_policy as Record<string, unknown>;
    expect(out.crs_policy).toEqual({ outbound_anomaly_score_threshold: "8", max_num_args: "400" });
    expect(out.some_future_key).toEqual({ a: 1 });
  });

  it("does not resurrect a key the form owns and switched off", () => {
    const site = stored({
      mode: "learning", paranoia_level: 2, anomaly_threshold: 10,
      rate_limit: { global: { rps: 1, burst: 1 }, per_ip: { rps: 1, burst: 1 } },
    });
    const f = siteToForm(site);
    f.rate_limit_enabled = false;
    const out = formToPayload(f).waf_policy as Record<string, unknown>;
    expect(out.rate_limit).toBeUndefined();
  });

  it("never lets a preserved key overwrite what the form wrote", () => {
    const f = emptyForm();
    f.preserved_policy = { mode: "off", crs_policy: { x: "1" } };
    const out = formToPayload(f).waf_policy as Record<string, unknown>;
    expect(out.mode).toBe(f.mode);
    expect(out.crs_policy).toEqual({ x: "1" });
  });

  it("FORM_MANAGED_POLICY_KEYS names every key formToPayload can write", async () => {
    // With every switch on, formToPayload writes every key it knows. A key it
    // writes that the set does not name would be treated as "not ours" and
    // could be resurrected from the stored policy after being switched off.
    const { FORM_MANAGED_POLICY_KEYS } = await import("../siteConfig");
    const f = emptyForm() as unknown as Record<string, unknown>;
    for (const k of Object.keys(f)) if (typeof f[k] === "boolean") f[k] = true;
    for (const mode of ["allow", "block"]) {
      (f as { geo_mode: string }).geo_mode = mode;
      const keys = Object.keys(formToPayload(f as unknown as SiteForm).waf_policy);
      for (const k of keys) expect(FORM_MANAGED_POLICY_KEYS.has(k), `unlisted key ${k}`).toBe(true);
    }
    // And by source: every `waf_policy.X =` the builder assigns.
    const { readFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    const src = readFileSync(join(__dirname, "../siteConfig.ts"), "utf8");
    for (const m of src.matchAll(/waf_policy\.([a-z_]+)\s*=/g)) {
      expect(FORM_MANAGED_POLICY_KEYS.has(m[1]), `unlisted key ${m[1]}`).toBe(true);
    }
  });
});
