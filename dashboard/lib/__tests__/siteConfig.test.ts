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
