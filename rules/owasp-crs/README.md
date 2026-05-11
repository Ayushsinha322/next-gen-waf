# OWASP Core Rule Set v4.7.0 — Sentinel WAF bundle

This directory contains the full **OWASP CRS v4.7.0** rule set, bundled verbatim
from the upstream release at
https://github.com/coreruleset/coreruleset/releases/tag/v4.7.0

Files are used **read-only** by Sentinel. Do not edit them here; apply
customisations via exclusion rules in your site's SRL rule files or via the
`rules/custom/` directory.

---

## Directory layout

```
rules/owasp-crs/
├── crs-setup.conf.example          ← CRS paranoia-level / score settings (reference only)
├── README.md                       ← this file
├── CHANGES.md                      ← upstream CRS changelog
└── rules/
    ├── REQUEST-901-INITIALIZATION.conf
    ├── REQUEST-905-COMMON-EXCEPTIONS.conf
    ├── REQUEST-911-METHOD-ENFORCEMENT.conf
    ├── REQUEST-913-SCANNER-DETECTION.conf
    ├── REQUEST-920-PROTOCOL-ENFORCEMENT.conf
    ├── REQUEST-921-PROTOCOL-ATTACK.conf
    ├── REQUEST-922-MULTIPART-ATTACK.conf
    ├── REQUEST-930-APPLICATION-ATTACK-LFI.conf
    ├── REQUEST-931-APPLICATION-ATTACK-RFI.conf
    ├── REQUEST-932-APPLICATION-ATTACK-RCE.conf
    ├── REQUEST-933-APPLICATION-ATTACK-PHP.conf
    ├── REQUEST-934-APPLICATION-ATTACK-GENERIC.conf
    ├── REQUEST-941-APPLICATION-ATTACK-XSS.conf
    ├── REQUEST-942-APPLICATION-ATTACK-SQLI.conf   ← SQL injection rules
    ├── REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
    ├── REQUEST-944-APPLICATION-ATTACK-JAVA.conf
    ├── REQUEST-949-BLOCKING-EVALUATION.conf       ← anomaly score → block decision
    ├── RESPONSE-950-DATA-LEAKAGES.conf
    ├── RESPONSE-951-DATA-LEAKAGES-SQL.conf
    ├── RESPONSE-952-DATA-LEAKAGES-JAVA.conf
    ├── RESPONSE-953-DATA-LEAKAGES-PHP.conf
    ├── RESPONSE-954-DATA-LEAKAGES-IIS.conf
    ├── RESPONSE-955-WEB-SHELLS.conf
    ├── RESPONSE-959-BLOCKING-EVALUATION.conf
    ├── RESPONSE-980-CORRELATION.conf
    └── *.data                                     ← word-list files (@pmFromFile data)
```

---

## Configuring in sentinel.yaml

Add the CRS `.conf` files to a site's `waf.rules` list in the order shown
below (initialization first, blocking evaluation last):

```yaml
sites:
  - id: my-app
    domains: [example.com]
    upstream:
      servers: [{host: 127.0.0.1, port: 8080}]
    waf:
      mode: blocking          # or "learning" for detection-only
      paranoia_level: 1       # 1-4 (higher = more rules, more false positives)
      anomaly_threshold: 5    # block if anomaly score >= this (CRS PL1 default)
      rules:
        # CRS v4 -- load in numerical order
        - rules/owasp-crs/rules/REQUEST-901-INITIALIZATION.conf
        - rules/owasp-crs/rules/REQUEST-905-COMMON-EXCEPTIONS.conf
        - rules/owasp-crs/rules/REQUEST-911-METHOD-ENFORCEMENT.conf
        - rules/owasp-crs/rules/REQUEST-913-SCANNER-DETECTION.conf
        - rules/owasp-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
        - rules/owasp-crs/rules/REQUEST-921-PROTOCOL-ATTACK.conf
        - rules/owasp-crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf
        - rules/owasp-crs/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf
        - rules/owasp-crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf
        - rules/owasp-crs/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf
        - rules/owasp-crs/rules/REQUEST-934-APPLICATION-ATTACK-GENERIC.conf
        - rules/owasp-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf
        - rules/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
        - rules/owasp-crs/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
        - rules/owasp-crs/rules/REQUEST-944-APPLICATION-ATTACK-JAVA.conf
        - rules/owasp-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf
        - rules/owasp-crs/rules/RESPONSE-950-DATA-LEAKAGES.conf
        - rules/owasp-crs/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf
        - rules/owasp-crs/rules/RESPONSE-952-DATA-LEAKAGES-JAVA.conf
        - rules/owasp-crs/rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf
        - rules/owasp-crs/rules/RESPONSE-954-DATA-LEAKAGES-IIS.conf
        - rules/owasp-crs/rules/RESPONSE-955-WEB-SHELLS.conf
        - rules/owasp-crs/rules/RESPONSE-959-BLOCKING-EVALUATION.conf
        - rules/owasp-crs/rules/RESPONSE-980-CORRELATION.conf
```

---

## Importer compatibility matrix

Sentinel's `sentinel-rules` crate includes a ModSecurity CRS importer
(`crs_compat::import_secrule_conf`). The table below tracks which CRS
features are currently handled.

### Fully supported

| Feature | Notes |
|---|---|
| `SecRule TARGETS "@rx pattern" "actions"` | Core rule form |
| `SecRule ... "@pm word1 word2"` | Aho-Corasick multi-string match |
| `SecRule ... "@contains"` | Mapped to ContainsWord |
| `SecRule ... "@beginsWith"` / `@endsWith` | Mapped to anchored regex |
| `SecRule ... "@streq"` / `@eq` | Mapped to Eq |
| `SecRule ... "@ge N"` | Integer comparison |
| `SecRule ... "@within"` | Mapped to ContainsWord list |
| `SecRule ... "@unconditionalMatch"` | Always-fires stub |
| Actions: `id`, `phase`, `block`, `pass`, `allow`, `log`, `nolog` | |
| Actions: `msg`, `severity`, `tag` | |
| Actions: `setvar:tx.xxx=+N` | Simple score deltas |
| Targets: `ARGS`, `ARGS_NAMES`, `REQUEST_BODY`, `REQUEST_URI`, `REQUEST_HEADERS`, `REQUEST_COOKIES`, `RESPONSE_HEADERS`, `RESPONSE_BODY`, `REMOTE_ADDR`, `TX` | |
| `SecRuleEngine On|Off|DetectionOnly` | |
| `SecRequestBodyAccess On|Off` | |
| `SecMarker`, `SecAction` | |
| Comments (`#`) | |
| Multi-line rules (backslash continuation) | |

### Stubbed / partial

| Feature | Current behaviour | Planned fix |
|---|---|---|
| `@detectSQLi` | Regex stub `(select\|union\|...)` | Phase 4: libinjection Rust binding |
| `@detectXSS` | Same stub | Phase 4 |
| `@pmFromFile file.data` | Pattern ignored; `.data` files not loaded | Phase 1 follow-up |
| `setvar` with `%{tx.xxx}` interpolation | `+N` deltas work; `%{...}` expansion skipped | Phase 1 follow-up |
| `chain` | Imports lead rule only, emits warning | Phase 1 follow-up |
| `skipAfter:MARKER` | Ignored (all matching rules evaluate) | Phase 1 follow-up |
| Transforms `t:utf8toUnicode`, `t:removeNulls`, etc. | Skipped | Phase 1 follow-up |
| `capture` / `TX.0` back-references | Skipped | Phase 2+ |
| `multiMatch` | Single-pass evaluation | Phase 2+ |
| Paranoia level gating via `TX:DETECTION_PARANOIA_LEVEL` | Rule always evaluates regardless of PL | Phase 1 follow-up |
| XML targets | Skipped | Phase 6 |
| File upload targets (`FILES*`, `MULTIPART_*`) | Skipped | Phase 3 |

### Not supported

| Feature | Reason |
|---|---|
| `SecComponentSignature` | Informational only |
| `SecDefaultAction` | Not yet consumed by VM |
| Lua script operators (`@lua`) | WASM plugins are the Sentinel extension point |

---

## Running tests

```bash
# From repo root -- verify the CRS importer smoke-test passes:
cargo test -p sentinel-rules -- crs_import
```

---

## Updating CRS

Download the new tarball, extract, and overwrite the `rules/` directory:

```bash
NEW_VER=4.x.x
# fetch https://github.com/coreruleset/coreruleset/archive/refs/tags/v${NEW_VER}.tar.gz
# extract, then:
cp coreruleset-${NEW_VER}/rules/*.conf   sentinel-waf/rules/owasp-crs/rules/
cp coreruleset-${NEW_VER}/rules/*.data   sentinel-waf/rules/owasp-crs/rules/
cp coreruleset-${NEW_VER}/crs-setup.conf.example sentinel-waf/rules/owasp-crs/
```

---

*Bundled from OWASP CRS v4.7.0 — Apache-2.0 license.*
*Sentinel WAF importer: `crates/sentinel-rules/src/crs_compat/`.*
