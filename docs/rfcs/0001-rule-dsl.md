# RFC 0001 — Sentinel Rule DSL

| Field      | Value                         |
|------------|-------------------------------|
| RFC        | 0001                          |
| Status     | Draft                         |
| Authors    | Sentinel WAF Contributors     |
| Created    | 2026-05-11                    |
| Implements | Phase 1 — Rule Engine         |

---

## Summary

Define the Sentinel Rule Language (SRL) — a domain-specific language for
writing WAF detection rules that:

1. Compiles to a compact bytecode evaluated by `sentinel-rules`.
2. Is a **strict superset** of ModSecurity/OWASP CRS SecRule syntax so that
   the 900+ CRS rules import without modification.
3. Adds native constructs CRS lacks: pattern variables, typed targets, scoring
   directives, plugin call-out, and ML gate conditions.
4. Is human-readable and LLM-friendly (the copilot generates SRL).

---

## Motivation

### Why not use ModSecurity/Coraza directly?

| Concern | ModSecurity / Coraza | Sentinel SRL |
|---|---|---|
| Performance | Interpreted Lua/C chain | Compiled bytecode, SIMD pattern match |
| Type safety | String everything | Typed targets (IP, jwt, json path) |
| ML integration | None | First-class `ml_score()` condition |
| Plugin call-out | Hooks only | `plugin_call(name, args)` directive |
| Hot-reload | Restart required | Atomic swap on SIGHUP / gRPC push |
| Composition | No modules | `include`, `import`, parameterized macros |

We still need **full backward-compat** with CRS syntax so the 900+ existing
CRS rules work on day 0 without a rewrite.

---

## Rule File Format

Rule files use the `.srl` extension. They are UTF-8 text.  The CRS importer
reads `.conf` files and emits equivalent `.srl` AST nodes.

```srl
# comments start with #

# --- Meta directives ---

SecRuleEngine On            # CRS-compatible, parsed as `engine: blocking`
SecRequestBodyAccess On

# --- Variables ---

# Define a named pattern set (replaces SecRule TX:SQL_INJECTION_SCORE)
var SQL_SCORE : score = 0

# --- Rules ---

rule 942100 {
    phase     : request_body
    targets   : ARGS | ARGS_NAMES | REQUEST_BODY
    operator  : rx /(?i)(select|union|insert|update|delete|drop|exec)\s/
    score     : +5
    severity  : critical
    message   : "SQL injection attempt"
    tag       : ["owasp-crs/v4", "sqli", "pci-dss-6.5.1"]
    action    : score                 # accumulate, don't block immediately
}

rule 942101 {
    phase  : request_body
    targets: ARGS
    operator: contains_word ["xp_cmdshell", "exec(", "sp_executesql"]
    score  : +8
    action : block                    # block immediately regardless of threshold
    message: "SQL stored procedure injection"
}

# Anomaly threshold check — fires at end of request_headers / request_body
rule 980130 {
    phase   : request_body
    operator: anomaly_score >= 5
    action  : block
    message : "Anomaly score threshold exceeded"
}

# ML gate — block if payload classifier > 0.87
rule 990010 {
    phase   : request_body
    operator: ml_score("payload_classifier_v1") >= 0.87
    action  : block
    message : "ML: high-confidence attack payload"
    tag     : ["ml"]
}

# Virtual patch — target a known CVE in a specific app
virtual_patch CVE-2024-12345 {
    phase   : request_headers
    targets : REQUEST_URI
    operator: rx /\/vulnerable\.php\?.*cmd=/
    action  : block
    message : "Virtual patch: CVE-2024-12345 exploitation attempt"
    expires : 2025-12-31
}

# Rate limit rule (integrates with sentinel-modules/rate_limit)
rule 910010 {
    phase    : request_headers
    operator : rate_limit_exceeded(per_ip, rps=50, burst=100)
    action   : challenge(native_pow)
    message  : "Rate limit exceeded"
}

# Plugin call-out
rule 990100 {
    phase   : request_headers
    targets : REQUEST_HEADERS:Authorization
    operator: exists
    action  : plugin_call("jwt-validator", { "fail_action": "block" })
}
```

---

## Syntax Grammar (PEG / nom)

```peg
rule_file   = { directive | rule_def | virtual_patch | comment | NEWLINE }*

rule_def    = "rule" WS+ rule_id WS* "{" rule_body "}"
rule_id     = ASCII_DIGIT+

virtual_patch = "virtual_patch" WS+ cve_id WS* "{" rule_body "}"
cve_id      = "CVE-" ASCII_DIGIT+ "-" ASCII_DIGIT+

rule_body   = { rule_field }+

rule_field  =
    "phase"    ":" phase_name
  | "targets"  ":" target_expr
  | "operator" ":" operator_expr
  | "score"    ":" score_expr
  | "severity" ":" severity_keyword
  | "message"  ":" quoted_string
  | "action"   ":" action_expr
  | "tag"      ":" "[" { quoted_string "," }* "]"
  | "expires"  ":" date_literal

phase_name = "connection" | "request_headers" | "request_body"
           | "upstream" | "response_headers" | "response_body" | "logging"

target_expr = target_name { ("|" | "&") target_name }*

target_name =
    "ARGS" | "ARGS_NAMES" | "REQUEST_HEADERS" ( ":" header_name )?
  | "REQUEST_BODY" | "REQUEST_URI" | "REQUEST_COOKIES" ( ":" cookie_name )?
  | "RESPONSE_HEADERS" ( ":" header_name )? | "RESPONSE_BODY"
  | "IP" | "GEO" | "TX" ":" var_name

operator_expr =
    "rx" WS+ "/" regex_body "/"  regex_flags?
  | "contains_word" WS+ word_list
  | "eq" WS+ value
  | "ge" WS+ value
  | "exists"
  | "anomaly_score" WS+ comparison WS+ INTEGER
  | "ml_score" "(" string ")" WS+ comparison WS+ FLOAT
  | "rate_limit_exceeded" "(" rate_args ")"
  | "!(" operator_expr ")"     # negation

action_expr =
    "score"
  | "block"
  | "allow"
  | "log"
  | "challenge" "(" challenge_mode ")"
  | "plugin_call" "(" quoted_string "," json_object ")"
  | "redirect" "(" url ")"

score_expr = ("+" | "-") INTEGER

directive  = secrule_compat_directive | native_directive

secrule_compat_directive =
    "SecRuleEngine" WS+ ("On" | "Off" | "DetectionOnly")
  | "SecRequestBodyAccess" WS+ ("On" | "Off")
  | "SecResponseBodyAccess" WS+ ("On" | "Off")
  | "SecDefaultAction" WS+ quoted_string
  | "SecRule" WS+ target_expr WS+ quoted_regex WS+ quoted_action_str
  | "SecAction" WS+ quoted_action_str
  | "SecMarker" WS+ quoted_string
  | "Include" WS+ file_glob

native_directive =
    "var" WS+ var_name ":" var_type "=" value
  | "import" WS+ module_path
  | "macro" WS+ macro_name "(" params ")" "{" rule_body "}"
```

---

## Compilation Pipeline

```
.srl / .conf files
      │
      ▼
  [ Parser ] — nom or pest (TBD, see §Decision below)
      │  AST
      ▼
  [ Semantic Analysis ]
  • Resolve targets to typed enums
  • Validate operator ↔ target compatibility
  • Check score/action consistency
  • Inline macros
      │  Typed AST
      ▼
  [ Optimiser ]
  • Merge adjacent rx operators → Aho-Corasick set
  • Hoist phase-static conditions
  • Dead-code elimination
      │  Optimised AST
      ▼
  [ Bytecode Emitter ]
  • Emit SRL-VM instructions (see §VM below)
  • Bundle into ConfigBundle bytes (sent via gRPC)
      │  Bytecode blob
      ▼
  sentinel-rules VM (per request, zero-copy)
```

---

## SRL-VM Instruction Set

The SRL-VM is a simple stack machine with 32-bit opcodes.  It is intentionally
minimal — complex logic (ML, plugin) dispatches back to host functions.

| Opcode | Operands | Description |
|--------|----------|-------------|
| `LOAD_TARGET` | target_id | Push the target value(s) onto the eval stack |
| `MATCH_RX` | pattern_id | Pop top, apply regex, push bool |
| `MATCH_MULTI` | set_id | Pop top, apply AC set, push bool |
| `MATCH_EQ` | literal | Pop top, compare, push bool |
| `LOAD_SCORE` | — | Push current anomaly score |
| `CMP_GE` | threshold | Pop, compare ≥ threshold, push bool |
| `ML_SCORE` | model_id | Push ML score for model_id (host call) |
| `RATE_CHECK` | window_id | Push bool (host call into rate-limit module) |
| `AND` | — | Pop 2 bools, push AND |
| `OR` | — | Pop 2 bools, push OR |
| `NOT` | — | Pop bool, push NOT |
| `SCORE_ADD` | delta | If top is true, add delta to anomaly score |
| `ACTION_BLOCK` | — | Set WafDecision::Block on context |
| `ACTION_CHALLENGE`| mode | Set WafDecision::Challenge |
| `ACTION_LOG` | — | Always allow, force log |
| `PLUGIN_CALL` | plugin_id, arg_id | Dispatch to WASM plugin (host call) |
| `JMP_IF_FALSE` | offset | Short-circuit rule chain |
| `RULE_END` | rule_id | Commit rule match if decision pending |

---

## Parser Decision: `nom` vs `pest`

| | `nom` | `pest` |
|---|---|---|
| Error messages | Manual, verbose | Auto-generated, clear |
| Combinator style | Code, flexible | Grammar file, declarative |
| Performance | Excellent (zero-copy) | Good (allocates grammar) |
| Error recovery | Must implement | Built-in (`SILENT`) |
| Streaming input | Yes | No |
| **Verdict** | **Chosen** | Alternative |

**Decision: `nom`.**  The SRL syntax is regular enough that nom combinators are
straightforward. nom gives zero-copy parsing of the raw rule bytes (critical at
startup with 900+ CRS rules) and integrates naturally with the bytecode emitter
operating on `Bytes`.

Use `pest` as a fallback if partial-parse error recovery proves difficult to
implement cleanly in nom.

---

## CRS Compatibility Layer

The CRS importer reads ModSecurity `.conf` files and maps each `SecRule`
directive to an SRL rule node:

```
SecRule ARGS "@rx (?i)select.*from" \
  "id:942100,phase:2,block,msg:'SQLi',severity:CRITICAL,tag:owasp-crs"
```

Maps to:

```srl
rule 942100 {
    phase    : request_body
    targets  : ARGS
    operator : rx /(?i)select.*from/
    action   : block
    severity : critical
    message  : "SQLi"
    tag      : ["owasp-crs"]
}
```

The importer:
- Handles the full SecRule chain (`chain`, `skip`, `skipAfter`, `setvar`).
- Maps `TX` variables to SRL score variables.
- Preserves all IDs (essential for false-positive reporting).
- Emits warnings for directives with no SRL equivalent.

---

## File Layout (`crates/sentinel-rules/src/`)

```
sentinel-rules/src/
├── lib.rs              — public API: load_ruleset(), compile(), RuleEngine
├── dsl/
│   ├── mod.rs          — exports
│   ├── ast.rs          — typed AST nodes
│   ├── parser.rs       — nom parser → AST
│   └── error.rs        — ParseError with line/col
├── compiler/
│   ├── mod.rs          — semantic analysis + bytecode emit
│   ├── analysis.rs     — type checking, macro expansion
│   ├── optimizer.rs    — AC merge, phase hoisting
│   ├── emitter.rs      — AST → SRL-VM bytecode
│   └── vm.rs           — bytecode interpreter (hot path)
├── crs_compat/
│   ├── mod.rs
│   ├── importer.rs     — SecRule → SRL AST
│   └── secrule.rs      — SecRule directive parser
└── patterns/
    └── mod.rs          — pattern set registry (Aho-Corasick pools)
```

---

## Implementation Schedule

| Phase | Milestone | Target |
|-------|-----------|--------|
| 1a | `dsl/parser.rs` — parse full SRL grammar (no CRS yet) | Week 1 |
| 1b | `compiler/analysis.rs` — semantic checks | Week 1 |
| 1c | `compiler/emitter.rs` + `vm.rs` — first rules execute | Week 2 |
| 1d | `crs_compat/importer.rs` — import OWASP CRS v4 | Week 3 |
| 1e | Phase-pipeline wiring in `sentinel-proxy` | Week 3 |
| 1f | First full request blocked by CRS rule 942100 | Week 4 |

---

## Open Questions

1. **Streaming body inspection**: Very large request bodies cannot be fully
   buffered.  We need a chunked-inspection API in the VM.  Proposal: split
   `request_body` phase into `request_body_chunk` (per-chunk) + `request_body_end`
   (final score).

2. **Rule ordering within a phase**: CRS relies on rule ID ordering within a
   phase.  The VM should sort rules by ID at compile time.

3. **setvar / TX chains**: CRS uses chained rules that set `TX` variables
   across rules.  We need scoped transaction variables in the VM's execution
   context (already planned in `RequestContext::rule_matches`).

4. **Concurrency**: The compiled bytecode blob is immutable and shared across
   all worker threads via `Arc`.  Rule variables (`TX` state) live in
   `RequestContext` which is per-request.  No locks on the hot path.
