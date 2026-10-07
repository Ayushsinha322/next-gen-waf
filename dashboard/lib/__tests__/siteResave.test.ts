import { describe, expect, it } from "vitest";
import { formToPayload, siteToForm } from "../siteConfig";
import type { Site } from "../api";

/** A site exactly as deploy/package/customer/onboard-site.sh creates it: no
 *  security_headers, no tls, a threshold of its own, a 1 MiB body limit. */
function scriptSite(waf: Record<string, unknown> = {}): Site {
  return {
    id: "s1", tenant_id: "t1", name: "shop", domains: ["shop.example.in"], status: "active",
    created_at: "", updated_at: "",
    upstream: {
      load_balancer: "round_robin",
      servers: [{ host: "10.0.0.5", port: 8080, weight: 1, tls: false }],
      health_check: { path: "/", interval: "10s", timeout: "3s" },
      timeout_secs: 30, connect_timeout_secs: 5,
      proxy: { websocket: false, keepalive: true },
    },
    waf_policy: {
      mode: "learning", paranoia_level: 2, anomaly_threshold: 10,
      max_body_size: 1048576, max_uri_length: 8192, max_header_count: 100,
      allowed_methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
      ...waf,
    } as unknown as Site["waf_policy"],
  };
}

const policyOf = (s: Site) => formToPayload(siteToForm(s)).waf_policy as Record<string, unknown>;

describe("saving a site without edits changes nothing it enforces", () => {
  it("a script-created site gains no HSTS, cookie flags or other headers", () => {
    const stored = scriptSite();
    const saved = policyOf(stored);
    // 1.1.16 wrote one-year HSTS and `* HttpOnly SameSite=Lax` here, which the
    // data plane appends to every Set-Cookie (breaking JS-read CSRF cookies).
    expect(saved.security_headers).toBeUndefined();
    for (const k of Object.keys(stored.waf_policy)) {
      expect(saved[k], k).toEqual((stored.waf_policy as Record<string, unknown>)[k]);
    }
  });

  it("a site stored without a threshold keeps running the server's 10, not 5", () => {
    const stored = scriptSite();
    delete (stored.waf_policy as Record<string, unknown>).anomaly_threshold;
    const saved = policyOf(stored);
    expect(saved.anomaly_threshold).toBeUndefined();

    const f = siteToForm(stored);
    expect(f.anomaly_threshold).toBe(10);
    f.anomaly_threshold = 7; // an actual edit is written
    expect((formToPayload(f).waf_policy as Record<string, unknown>).anomaly_threshold).toBe(7);
  });

  it("a body limit of 0 (no limit) or under 0.5 MiB is kept, not reset to 10 MiB", () => {
    expect(policyOf(scriptSite({ max_body_size: 0 })).max_body_size).toBe(0);
    expect(policyOf(scriptSite({ max_body_size: 262144 })).max_body_size).toBe(262144);
  });

  it("the timeouts a site runs are written back unchanged", () => {
    const up = formToPayload(siteToForm(scriptSite())).upstream as Record<string, unknown>;
    expect(up.timeout_secs).toBe(30);
    expect(up.connect_timeout_secs).toBe(5);
  });
});

describe("clearing a header setting sticks", () => {
  it("cookie flags cleared in the form are removed, and stay removed after a reload", () => {
    const stored = scriptSite({
      security_headers: { cookie_flags: "* HttpOnly SameSite=Lax", referrer_policy: "no-referrer" },
    });
    const f = siteToForm(stored);
    expect(f.cookie_flags).toBe("* HttpOnly SameSite=Lax");
    f.cookie_flags = "";
    const saved = formToPayload(f).waf_policy as Record<string, unknown>;
    const sh = (saved.security_headers ?? {}) as Record<string, unknown>;
    expect(sh.cookie_flags).toBeUndefined();
    expect(sh.referrer_policy).toBe("no-referrer");

    const reloaded = siteToForm({ ...stored, waf_policy: saved as unknown as Site["waf_policy"] });
    expect(reloaded.cookie_flags).toBe("");
  });
});

describe("a new site starts without an origin", () => {
  it("the wizard no longer pre-fills the WAF's own listener as the origin", async () => {
    const { emptyForm } = await import("../siteConfig");
    const f = emptyForm();
    // 127.0.0.1:8080 was the data plane's own HTTP listener: an unedited save
    // made the WAF proxy to itself.
    expect(f.servers.every(s => s.host === "")).toBe(true);
  });
});

describe("1.1.18 new-site defaults", () => {
  it("a new site gets the classifier at the benchmarked posture and no cookie flags", async () => {
    const { emptyForm } = await import("../siteConfig");
    const f = emptyForm();
    expect(f.ml_enabled).toBe(true);
    expect(f.ml_sensitivity).toBe(0.9);
    // `* HttpOnly SameSite=Lax` broke JS-read CSRF cookies on every site.
    expect(f.cookie_flags).toBe("");
  });

  it("a stored site without ML shows ML off, and saving it unedited does not turn it on", () => {
    const stored = scriptSite();
    const f = siteToForm(stored);
    expect(f.ml_enabled).toBe(false);
    expect(policyOf(stored).ml).toBeUndefined();
  });
});
