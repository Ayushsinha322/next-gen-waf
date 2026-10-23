#!/usr/bin/env python3
"""Run the OWASP CRS regression tests against a running data plane.

    crs-regression.py TESTS --port 18080 (--container NAME | --dp-log FILE)
                      [--waf-log-volume VOLUME | --waf-log FILE]
                      [--inventory inventory.json | --rule-file R.conf ...]
                      [--baseline FILE] [--write-baseline FILE]
                      [--json results.json] [--only 920420,920440]
                      [--engine LABEL] [--binary PATH] [--config PATH]
    crs-regression.py --export TESTS_DIR --suite-version 4.7.0 OUT.json

TESTS is CRS's own `tests/regression/tests` for the shipped CRS version
(reading it needs PyYAML), or the JSON bundle --export makes of it, which
needs nothing beyond the standard library: CI runs the bundle.

The data plane's request log is its stdout (`message: "request"` lines):
--container streams it with `docker logs`, --dp-log tails a file it is
redirected to. waf.log (the detection log, in SENTINEL_LOG_DIR) is optional
but strongly recommended: --waf-log-volume reads it from a Docker volume,
--waf-log from a file.

WHY THIS AND NOT go-ftw

go-ftw is the CRS project's runner, and these are its test files, unmodified.
go-ftw decides which rules fired by reading a ModSecurity error log between two
marker requests (`X-CRS-Test: <uuid>`), looking for `[id "942100"]`. The data
plane logs neither, so this runner sends the tests one at a time and reads the
rule IDs from the data plane's own logs. Requests are built as go-ftw builds
them (ftwhttp/request.go): header autocompletion, a urlencoded body escaped, a
multipart body's line feeds made CRLF.

CORRELATION

Each request carries `X-CRS-Test: <uuid>` — the header go-ftw's markers carry —
except a test that sends a raw request or asks for its headers exactly. An
access-log line is taken only if it names the method and path that were sent.
waf.log records a request's headers when it blocked or would have blocked it;
there the line must carry the same marker, and the case is recorded with
correlation `marker`. Any other case is `sequence`: one request at a time,
matched by method and path. A line whose marker differs is reported as
unsupported ("correlation mismatch"), never silently used.

WHAT EACH CASE IS

  pass         every expected rule ID fired and no forbidden one did
  fail         an expected ID did not fire, or a forbidden one did
  unsupported  the test cannot say anything about this engine; `reason` says why:
                 rule not loaded by the product
                 response rule: needs CRS's echo backend
                 no access-log line: rejected before the WAF
                 answered before the rule engine (threat intel / IP reputation)
                 the logs list only part of the rules that matched
                 correlation mismatch
  skipped      not run (--only)

A status-code expectation is reported separately: CRS writes those for
Apache's behaviour, and a different HTTP stack answers differently without
the rule being wrong.

EXIT STATUS — the CI policy

  0  no regression: every case that is not a pass is in the baseline with the
     same result and reason (without --baseline: no case failed)
  1  regression: a case failed, or became unsupported, that the baseline does
     not list that way
  2  the run says nothing: the suite differs from the baseline's, or most
     requests produced no access-log line (the harness, not the engine)

A case that passes but is listed in the baseline is reported as fixed; it
does not fail the run. --write-baseline records every non-pass case.
"""

import argparse
import atexit
import base64
import hashlib
import json
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

LOG_WAIT_SECS = 3.0
# How long to wait for a request's waf.log line when one should exist. Lines
# are written as the request completes; the readers poll every 50 ms.
WAF_LOG_WAIT_SECS = 0.5
MARKER = "X-CRS-Test"


# ---------------------------------------------------------------------------
# The suite
# ---------------------------------------------------------------------------

def load_suite(path):
    """(meta, files) from a YAML tests directory or a JSON bundle."""
    p = Path(path)
    if p.is_file():
        bundle = json.loads(p.read_text())
        return bundle["meta"], bundle["files"]
    import yaml  # only the YAML directory needs it

    files = []
    digest = hashlib.sha256()
    for f in sorted(p.rglob("*.yaml")):
        text = f.read_text()
        digest.update(str(f.relative_to(p)).encode() + b"\0" + text.encode())
        doc = yaml.safe_load(text)
        files.append({
            "file": str(f.relative_to(p)),
            "rule_id": int(doc.get("rule_id") or f.stem),
            "tests": doc.get("tests", []),
        })
    return {"suite_sha256": digest.hexdigest()}, files


def export_suite(tests_dir, version, out):
    meta, files = load_suite(tests_dir)
    meta["crs_version"] = version
    Path(out).write_text(json.dumps({"meta": meta, "files": files}, separators=(",", ":")) + "\n")
    cases = sum(len(t.get("stages", [])) for f in files for t in f["tests"])
    print(f"wrote {out}: CRS {version}, {len(files)} files, {cases} stages")


# ---------------------------------------------------------------------------
# Log readers
# ---------------------------------------------------------------------------

def _pump_requests(stream, out):
    for line in stream:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        fields = rec.get("fields", rec)
        if fields.get("message") == "request":
            out.put(fields)


def _pump_waf(stream, out):
    for line in stream:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        rid = rec.get("request_id")
        if rid:
            headers = {k.lower(): v for k, v in (rec.get("headers") or {}).items()}
            out[rid] = ({str(r.get("id")) for r in rec.get("rules") or []},
                        headers.get(MARKER.lower()))


def tail_file(path):
    """A line iterator over what is appended to `path` from now on."""
    while not os.path.exists(path):
        time.sleep(0.05)
    f = open(path, "r", errors="replace")
    f.seek(0, os.SEEK_END)
    pending = ""
    while True:
        chunk = f.readline()
        if not chunk:
            time.sleep(0.02)
            continue
        pending += chunk
        if pending.endswith("\n"):
            yield pending
            pending = ""


def start_request_reader(args, out):
    if args.dp_log:
        stream = tail_file(args.dp_log)
        threading.Thread(target=_pump_requests, args=(stream, out), daemon=True).start()
        return None
    proc = subprocess.Popen(
        ["docker", "logs", "-f", "--since", "1s", args.container],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    threading.Thread(target=_pump_requests, args=(proc.stdout, out), daemon=True).start()
    return proc


def start_waf_reader(args, out):
    if args.waf_log:
        stream = tail_file(args.waf_log)
        threading.Thread(target=_pump_waf, args=(stream, out), daemon=True).start()
        return None
    # A named container, removed by name on exit: stopping the `docker run`
    # client does not stop it (tail is PID 1 and ignores SIGTERM). busybox
    # `tail -F` polls once a second unless told otherwise.
    name = f"crs-regression-waflog-{os.getpid()}"
    atexit.register(subprocess.run, ["docker", "rm", "-f", name],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc = subprocess.Popen(
        ["docker", "run", "--rm", "-i", "--name", name, "-v", f"{args.waf_log_volume}:/l:ro",
         "alpine:latest", "tail", "-n0", "-s", "0.05", "-F", "/l/waf.log"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
    threading.Thread(target=_pump_waf, args=(proc.stdout, out), daemon=True).start()
    return proc


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

def go_query_unescape(text):
    """Go's url.QueryUnescape: None where it would fail (a malformed escape)."""
    hexdigits = set("0123456789abcdefABCDEF")
    i = 0
    while i < len(text):
        if text[i] == "%":
            if i + 2 >= len(text) or text[i + 1] not in hexdigits or text[i + 2] not in hexdigits:
                return None
            i += 3
        else:
            i += 1
    return urllib.parse.unquote_plus(text)


def go_encode_form(data):
    """go-ftw's encodeDataParameters for a urlencoded body: when the data holds
    no escape already, split on `&` and the first `=`, and QueryEscape each key
    and value (Go's QueryEscape = Python's quote_plus with nothing extra safe)."""
    text = data.decode("utf-8", "surrogateescape")
    if go_query_unescape(text) != text:
        return data

    def q(v):
        return urllib.parse.quote_plus(v, safe="", errors="surrogateescape")

    parts = []
    for token in text.split("&"):
        key, eq, value = token.partition("=")
        parts.append(q(key) + ("=" + q(value) if eq else ""))
    return "&".join(parts).encode("utf-8", "surrogateescape")


def build_request(inp, marker):
    """The raw bytes of one test request, as go-ftw builds them, plus the
    marker header when the test allows one (`marker` is None otherwise)."""
    if inp.get("encoded_request"):
        return base64.b64decode(inp["encoded_request"])
    method = inp.get("method", "GET")
    uri = str(inp.get("uri", "/"))
    version = inp.get("version", "HTTP/1.1")
    headers = dict(inp.get("headers") or {})
    data = inp.get("data")
    body = b""
    if data is not None:
        body = data.encode("utf-8", "surrogateescape") if isinstance(data, str) else bytes(data)
    autocomplete = inp.get("autocomplete_headers", True)
    if autocomplete and body and "content-type" not in {k.lower() for k in headers}:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    ctypes = [str(v) for k, v in headers.items() if k.lower() == "content-type"]
    if autocomplete and body and "application/x-www-form-urlencoded" in ctypes:
        body = go_encode_form(body)
    if any("multipart/form-data;" in v for v in ctypes):
        body = body.replace(b"\n", b"\r\n")
    if autocomplete:
        lower = {k.lower() for k in headers}
        if "content-length" not in lower and (
            body or method.upper() in ("POST", "PUT", "PATCH", "DELETE")
        ):
            headers["Content-Length"] = str(len(body))
        if "connection" not in lower:
            headers["Connection"] = "close"
    if marker:
        headers[MARKER] = marker
    head = f"{method} {uri} {version}\r\n"
    for k, v in headers.items():
        head += f"{k}: {v}\r\n"
    return head.encode("utf-8", "surrogateescape") + b"\r\n" + body


def send(addr, raw, timeout=10.0):
    """Send `raw`, read until the server closes; return the status code or None."""
    data = b""
    try:
        with socket.create_connection(addr, timeout=timeout) as s:
            # No half-close after sending: the server reads it as the client
            # going away and answers nothing. `Connection: close` ends the read.
            s.sendall(raw)
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
    except OSError:
        pass
    try:
        return int(data.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return None


def path_key(uri):
    """The first 32 characters of a request target's path, scheme and host,
    query and fragment removed: what the access log's capped path shows."""
    uri = str(uri or "")
    if "://" in uri.split("?", 1)[0]:
        rest = uri.split("://", 1)[1]
        uri = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
    return uri.split("#", 1)[0].split("?", 1)[0][:32]


def next_line_for(lines, inp):
    """The access-log line for the request just sent, or None. It must name
    the method and the start of the path that were sent (an encoded request's
    are not known here, so its next line is taken)."""
    raw = bool(inp.get("encoded_request"))
    method = str(inp.get("method", "GET")).upper()
    path = path_key(inp.get("uri", "/"))
    deadline = time.monotonic() + LOG_WAIT_SECS
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            return None
        try:
            rec = lines.get(timeout=left)
        except queue.Empty:
            return None
        if raw:
            return rec
        if str(rec.get("method", "")).upper() != method:
            continue
        if path_key(rec.get("uri")) != path:
            continue
        return rec


def wait_for(mapping, key, secs):
    deadline = time.monotonic() + secs
    while key not in mapping and time.monotonic() < deadline:
        time.sleep(0.01)
    return mapping.pop(key, None)


def ids_of(expectation, key):
    v = (expectation or {}).get(key)
    if v is None:
        # The older singular form: `expect_id: 920100`.
        v = (expectation or {}).get(key[:-1])
    if v is None:
        return set()
    if isinstance(v, (list, tuple)):
        return {int(x) for x in v}
    return {int(v)}


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

def case_key(c):
    return f"{c['file']}#{c['test']}#{c['stage']}"


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest() if path else None


def run_meta(args, suite_meta):
    meta = {
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "suite": suite_meta,
        "runner_sha256": file_sha256(__file__),
        "engine": args.engine,
        "binary_sha256": file_sha256(args.binary),
        "config_sha256": file_sha256(args.config),
    }
    try:
        meta["commit"] = subprocess.run(
            ["git", "-C", str(Path(__file__).parent), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        meta["commit"] = None
    if args.container:
        try:
            meta["image"] = subprocess.run(
                ["docker", "inspect", args.container, "--format",
                 "{{.Config.Image}} {{.Image}}"],
                capture_output=True, text=True, check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            meta["image"] = None
    return meta


def loaded_rule_ids(args):
    if args.inventory:
        inv = json.loads(Path(args.inventory).read_text())
        return {r["id"] for s in inv.get("sites", []) for r in s.get("rules", [])}
    if args.rule_file:
        ids = set()
        for f in args.rule_file:
            ids |= {int(m) for m in re.findall(r"\bid:(\d+)", Path(f).read_text())}
        return ids
    return None


def run(args):
    suite_meta, files = load_suite(args.tests)
    loaded = loaded_rule_ids(args)
    only = {int(x) for x in args.only.split(",")} if args.only else None
    meta = run_meta(args, suite_meta)

    lines, waf = queue.Queue(), {}
    procs = [start_request_reader(args, lines)]
    have_waf = bool(args.waf_log or args.waf_log_volume)
    if have_waf:
        procs.append(start_waf_reader(args, waf))
    time.sleep(2.0)  # let the readers attach before the first request

    cases = []
    for f in files:
        rule_id, family = f["rule_id"], f["file"].split("/")[0]
        for test in f["tests"]:
            for n, stage in enumerate(test.get("stages", [])):
                stage = stage.get("stage", stage)
                inp, out = stage.get("input", {}), stage.get("output", {})
                log = out.get("log", {}) or {}
                expect, forbid = ids_of(log, "expect_ids"), ids_of(log, "no_expect_ids")
                case = {"file": f["file"], "rule": rule_id, "test": test.get("test_id"),
                        "stage": n, "expect": sorted(expect), "forbid": sorted(forbid)}
                cases.append(case)
                if only is not None and rule_id not in only:
                    case["result"] = "skipped"
                    continue
                if family.startswith("RESPONSE-"):
                    case.update(result="unsupported", reason="response rule: needs CRS's echo backend")
                    continue
                if loaded is not None and (expect or {rule_id}) - loaded:
                    case.update(result="unsupported", reason="rule not loaded by the product")
                    continue
                marker = None
                if not inp.get("encoded_request") and inp.get("autocomplete_headers", True):
                    marker = str(uuid.uuid4())
                while not lines.empty():
                    lines.get_nowait()
                case["status"] = send((args.host, args.port), build_request(inp, marker))
                rec = next_line_for(lines, inp)
                if rec is None:
                    case.update(result="unsupported",
                                reason="no access-log line: rejected before the WAF")
                    continue
                # Threat intel and IP reputation answer before the rule engine
                # runs (their block tier is mode-independent by design).
                if str(rec.get("block_reason") or "").startswith(("threat intel:", "IP reputation:")):
                    case.update(result="unsupported",
                                reason="answered before the rule engine (threat intel / IP reputation)")
                    continue
                listed = {x for x in str(rec.get("rule_ids") or "").split(",") if x}
                total = int(rec.get("rule_matches") or 0)
                case["correlation"] = "sequence"
                if have_waf and total > 0:
                    found = wait_for(waf, rec.get("request_id"), WAF_LOG_WAIT_SECS)
                    if found is not None:
                        # waf.log carries the request's headers only on a block
                        # or a learning-mode would-block; a lower-scoring line
                        # has none, and so cannot confirm or contradict.
                        waf_ids, waf_marker = found
                        if marker and waf_marker is not None and waf_marker != marker:
                            case.update(result="unsupported", reason="correlation mismatch")
                            continue
                        listed |= waf_ids
                        if marker and waf_marker == marker:
                            case["correlation"] = "marker"
                fired = {int(x) for x in listed if x.isdigit()}
                case["fired"] = sorted(fired)
                case["matched_total"] = total
                missing, unwanted = expect - fired, forbid & fired
                # More rules matched than the logs list: an expected one may be
                # among the unlisted, a forbidden one may hide there.
                unlisted = total > len(listed)
                if unwanted:
                    case["result"] = "fail"
                elif unlisted and (missing or forbid):
                    case.update(result="unsupported",
                                reason="the logs list only part of the rules that matched")
                else:
                    case["result"] = "fail" if missing else "pass"
                if missing:
                    case["missing"] = sorted(missing)
                if unwanted:
                    case["unwanted"] = sorted(unwanted)
                want_status = out.get("status")
                if want_status is not None:
                    allowed = set(want_status) if isinstance(want_status, list) else {want_status}
                    case["status_ok"] = case["status"] in allowed
    for p in procs:
        if p is not None:
            p.terminate()
    return meta, cases


def report(cases):
    totals = Counter(c["result"] for c in cases)
    print(f"{len(cases)} cases: " + ", ".join(f"{k} {v}" for k, v in sorted(totals.items())))
    for reason, n in Counter(c.get("reason") for c in cases
                             if c["result"] == "unsupported").most_common():
        print(f"  unsupported: {n:5d}  {reason}")
    corr = Counter(c.get("correlation") for c in cases if c.get("correlation"))
    if corr:
        print("  correlation: " + ", ".join(f"{k} {v}" for k, v in sorted(corr.items())))
    status_checked = [c for c in cases if "status_ok" in c]
    if status_checked:
        print(f"  status expectations: {sum(c['status_ok'] for c in status_checked)}"
              f" of {len(status_checked)} as CRS expects (reported, not scored)")
    by_family = defaultdict(Counter)
    for c in cases:
        by_family[c["file"].split("/")[0]][c["result"]] += 1
    print()
    for fam in sorted(by_family):
        t = by_family[fam]
        print(f"{fam:52s} pass {t['pass']:4d}  fail {t['fail']:4d}  unsupported {t['unsupported']:4d}")
    fails = Counter(c["rule"] for c in cases if c["result"] == "fail")
    if fails:
        print("\nfailing rules: " + ", ".join(f"{r} x{n}" for r, n in sorted(fails.items())))


def gate(meta, cases, baseline_path):
    """The CI policy; returns the exit status."""
    ran = [c for c in cases if c["result"] != "skipped"]
    scorable = [c for c in ran if c.get("reason") not in (
        "response rule: needs CRS's echo backend", "rule not loaded by the product")]
    silent = [c for c in scorable if c.get("reason") == "no access-log line: rejected before the WAF"]
    if scorable and len(silent) > len(scorable) // 2:
        print(f"\nHARNESS: {len(silent)} of {len(scorable)} requests produced no access-log "
              "line — the data plane is not logging requests where this runner reads.")
        return 2
    if baseline_path is None:
        return 1 if any(c["result"] == "fail" for c in ran) else 0
    base = json.loads(Path(baseline_path).read_text())
    if base["meta"].get("suite") != meta["suite"]:
        print(f"\nSUITE: baseline is {base['meta'].get('suite')}, this run {meta['suite']}")
        return 2
    known = base["cases"]
    new, fixed = [], []
    for c in ran:
        b = known.get(case_key(c))
        if c["result"] == "pass":
            if b:
                fixed.append(c)
        elif b is None or b["result"] != c["result"] or b.get("reason") != c.get("reason"):
            new.append((c, b))
    for c in fixed:
        print(f"FIXED    {case_key(c)} (baseline: {known[case_key(c)]['result']})")
    for c, b in new:
        was = f"baseline: {b['result']}" if b else "baseline: pass"
        why = c.get("reason") or f"missing {c.get('missing')} unwanted {c.get('unwanted')}"
        print(f"NEW      {case_key(c)} {c['result']}: {why} ({was})")
    print(f"\ngate: {len(new)} new, {len(fixed)} fixed against {baseline_path}")
    return 1 if new else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("tests", help="CRS tests/regression/tests directory, or a --export bundle")
    ap.add_argument("out", nargs="?", help="with --export: the bundle to write")
    ap.add_argument("--export", action="store_true", help="bundle the YAML suite as JSON")
    ap.add_argument("--suite-version", help="with --export: the CRS version of the suite")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--container", help="data-plane container (docker logs)")
    src.add_argument("--dp-log", help="file the data plane's stdout is redirected to")
    waf = ap.add_mutually_exclusive_group()
    waf.add_argument("--waf-log-volume", help="the data plane's /var/log/sentinel volume")
    waf.add_argument("--waf-log", help="the data plane's waf.log")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18080)
    loaded = ap.add_mutually_exclusive_group()
    loaded.add_argument("--inventory", help="rules/inventory JSON for the site under test")
    loaded.add_argument("--rule-file", action="append", help="a rule file the site loads")
    ap.add_argument("--only", help="comma-separated rule IDs to run")
    ap.add_argument("--baseline", help="gate against this baseline (see EXIT STATUS)")
    ap.add_argument("--write-baseline", help="record this run's non-pass cases as a baseline")
    ap.add_argument("--json", help="write the run's metadata and every case to this file")
    ap.add_argument("--engine", help="what is under test, for the record (image, version)")
    ap.add_argument("--binary", help="the data-plane binary, recorded by hash")
    ap.add_argument("--config", help="the data-plane config, recorded by hash")
    args = ap.parse_args()

    if args.export:
        if not (args.out and args.suite_version):
            ap.error("--export needs OUT and --suite-version")
        export_suite(args.tests, args.suite_version, args.out)
        return 0
    if not (args.container or args.dp_log):
        ap.error("one of --container or --dp-log is required")

    meta, cases = run(args)
    report(cases)
    if args.json:
        Path(args.json).write_text(json.dumps({"meta": meta, "cases": cases}, indent=1))
    if args.write_baseline:
        known = {case_key(c): {k: c[k] for k in ("result", "reason", "missing", "unwanted") if k in c}
                 for c in cases if c["result"] not in ("pass", "skipped")}
        Path(args.write_baseline).write_text(
            json.dumps({"meta": meta, "cases": known}, indent=1, sort_keys=True) + "\n")
        print(f"\nwrote baseline {args.write_baseline}: {len(known)} non-pass cases")
    return gate(meta, cases, args.baseline)


if __name__ == "__main__":
    sys.exit(main())
