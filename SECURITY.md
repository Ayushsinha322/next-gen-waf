# Security Policy

Sentinel WAF is a security product. We take vulnerabilities in it — or in its
dependencies — seriously, and we appreciate responsible disclosure.

## Reporting a Vulnerability

**Do not open a public issue or merge request for security vulnerabilities.**

Instead, report privately to:

- **Email:** security@esds.co.in (CC: ayush.sinha@esds.co.in)
- Use the subject line `[Sentinel WAF] Security Report`.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce (proof-of-concept request, payload, or configuration).
- Affected component (data plane, control plane, dashboard) and version/commit.
- Any suggested remediation, if you have one.

If you wish to encrypt your report, request our PGP key in your first email.

## What to Expect

| Stage | Target |
|---|---|
| Acknowledgement of your report | within **3 business days** |
| Initial assessment & severity triage | within **7 business days** |
| Fix or mitigation plan | depends on severity; critical issues are prioritised |
| Coordinated disclosure | after a fix is available, by mutual agreement |

We will keep you informed throughout, and credit you in the release notes
(unless you prefer to remain anonymous).

## Scope

In scope:

- The Rust data plane (`crates/`) — request handling, rule engine, TLS, WASM sandbox.
- The Go control plane (`control-plane/`) — API, auth/RBAC, cluster, config sync.
- The dashboard (`dashboard/`).
- Bypasses of WAF detection (evasion of CRS/SRL rules), request smuggling, and
  authentication/authorisation flaws.

Out of scope:

- Vulnerabilities in third-party services used only for local development
  (DVWA, Juice Shop, demo upstreams).
- Findings that require physical access or a fully compromised host.
- Denial of service via unrealistic traffic volumes against a single dev node.

## Supported Versions

Sentinel WAF is under active development. Security fixes are applied to the
`main` branch. Until a tagged release line exists, only `main` is supported.

## Hardening Notes for Operators

- Never run with default or example secrets. `SENTINEL_DB_URL`, the JWT signing
  secret, and DB passwords must be set explicitly (the control plane refuses
  hardcoded dev credentials).
- Restrict `SENTINEL_CORS_ORIGINS` to known dashboard origins in production.
- Run the data plane with least privilege; kernel XDP requires elevated caps
  only when explicitly enabled (`--features kernel`).
