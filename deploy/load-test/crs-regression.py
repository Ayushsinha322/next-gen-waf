#!/usr/bin/env python3
"""Run the OWASP CRS regression tests against a running data plane.

    crs-regression.py TESTS_DIR --container NAME [--host 127.0.0.1] [--port 18080]
                      [--waf-log-volume VOLUME] [--inventory inventory.json]
                      [--only 920420,920440] [--json results.json]

TESTS_DIR is CRS's own `tests/regression/tests` for the shipped CRS version.
--container is the data plane whose access log (stdout) is read; --inventory is
`GET /api/v1/rules/inventory` for the site under test, used to tell a rule the
product does not load from a rule that failed.

WHY THIS AND NOT go-ftw

go-ftw is the CRS project's runner, and these are its test files, unmodified.
go-ftw decides which rules fired by reading a ModSecurity error log: it sends a
marker request carrying `X-CRS-Test: <uuid>` before and after each test, needs
the WAF to log that header value, and looks for `[id "942100"]` between the two
markers. The data plane logs neither in that form. It does log every request
with the IDs of every rule that matched it, so this runner sends the tests ONE
AT A TIME and takes the access-log line that follows each request as that
request's result. Nothing else may send requests to the data plane during a
run, or results are attributed to the wrong test.

Neither log lists every rule on a busy request: the access-log line names the
first 8 and counts them all, the detection log (waf.log) names the 20 that
scored most. --waf-log-volume (the volume holding /var/log/sentinel) lets the
runner take the longer list, by request ID. A case whose answer could be in
the part of the list no log kept is reported as unsupported, never as a fail.

THE SITE UNDER TEST must be set up as the CRS suite requires (its README): all
rules at paranoia level 4, detection only (learning mode), and the policy that
crs-setup.conf and REQUEST-901 would provide, which the product does not load.

WHAT EACH CASE IS

  pass         every expected rule ID fired and no forbidden one did
  fail         an expected ID did not fire, or a forbidden one did
  unsupported  the test cannot say anything about this engine, with the reason:
               the rule is not loaded by the product, it inspects a response
               (needs CRS's echo backend), or the request never reached the
               WAF (rejected by the HTTP layer: no access-log line)
  skipped      not run (--only)

A status-code expectation is checked and reported separately: CRS writes those
for Apache's behaviour in DetectionOnly mode, and a different HTTP stack
answers differently without the rule being wrong.
"""

import argparse
import atexit
import base64
import os
import json
import queue
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import Counter, defaultdict
from pathlib import Path

import yaml

LOG_WAIT_SECS = 3.0


def log_reader(container, out):
    """Stream the data plane's access-log lines (JSON on stdout) into `out`."""
    proc = subprocess.Popen(
        ["docker", "logs", "-f", "--since", "1s", container],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    )

    def pump():
        for line in proc.stdout:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            fields = rec.get("fields", rec)
            if fields.get("message") == "request":
                out.put(fields)

    threading.Thread(target=pump, daemon=True).start()
    return proc


def waf_log_reader(volume, out):
    """Stream waf.log (read-only, from the data plane's log volume) into the
    dict `out`: request ID -> every rule ID the line lists, as text.

    The reader is a named container, removed by name on exit: stopping the
    `docker run` client does not stop it (tail is PID 1 and ignores SIGTERM).
    busybox `tail -F` polls once a second unless told otherwise."""
    name = f"crs-regression-waflog-{os.getpid()}"
    atexit.register(subprocess.run, ["docker", "rm", "-f", name],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc = subprocess.Popen(
        ["docker", "run", "--rm", "-i", "--name", name, "-v", f"{volume}:/l:ro",
         "alpine:latest", "tail", "-n0", "-s", "0.05", "-F", "/l/waf.log"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        errors="replace",
    )

    def pump():
        for line in proc.stdout:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            rid = rec.get("request_id")
            if rid:
                out[rid] = {str(r.get("id")) for r in rec.get("rules") or []}

    threading.Thread(target=pump, daemon=True).start()
    return proc


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
    parts = []
    for token in text.split("&"):
        key, eq, value = token.partition("=")
        q = lambda v: urllib.parse.quote_plus(v, safe="", errors="surrogateescape")
        parts.append(q(key) + ("=" + q(value) if eq else ""))
    return "&".join(parts).encode("utf-8", "surrogateescape")


def build_request(inp, host):
    """The raw bytes of one test request, as go-ftw builds them
    (ftwhttp/request.go): header autocompletion, a urlencoded body escaped, a
    multipart body's line feeds made CRLF."""
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
    # go-ftw's autocompletion (ftwhttp/request.go): a urlencoded Content-Type
    # for a body that names none, Content-Length for a body or a body method,
    # and Connection: close.
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
    if host is not None:
        headers = {("Host" if k.lower() == "host" else k): (host if k.lower() == "host" else v)
                   for k, v in headers.items()}
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


def next_line_for(lines, inp):
    """The access-log line for the request just sent, or None.

    Lines are taken in order and must name the same method, so a line that
    arrives late is never attributed to the next test. (The logged URI is the
    proxy's own rendering of the target, so it is recorded for auditing, not
    compared.) An encoded request's
    method is not known here; its next line is taken as is."""
    method = None if inp.get("encoded_request") else str(inp.get("method", "GET"))
    deadline = time.monotonic() + LOG_WAIT_SECS
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            return None
        try:
            rec = lines.get(timeout=left)
        except queue.Empty:
            return None
        if method is None or str(rec.get("method", "")).upper() == method.upper():
            return rec


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


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("tests_dir")
    ap.add_argument("--container", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--host-header", default=None, help="replace each test's Host header")
    ap.add_argument("--waf-log-volume", help="the data plane's /var/log/sentinel volume")
    ap.add_argument("--inventory", help="rules/inventory JSON for the site under test")
    ap.add_argument("--only", help="comma-separated rule IDs to run")
    ap.add_argument("--json", help="write every case to this file")
    args = ap.parse_args()

    loaded = None
    if args.inventory:
        inv = json.loads(Path(args.inventory).read_text())
        loaded = {r["id"] for s in inv.get("sites", []) for r in s.get("rules", [])}
    only = {int(x) for x in args.only.split(",")} if args.only else None

    lines = queue.Queue()
    proc = log_reader(args.container, lines)
    waf_ids, waf_proc = {}, None
    if args.waf_log_volume:
        waf_proc = waf_log_reader(args.waf_log_volume, waf_ids)
    time.sleep(2.0)  # let both readers attach before the first request

    cases = []
    files = sorted(Path(args.tests_dir).rglob("*.yaml"))
    for path in files:
        doc = yaml.safe_load(path.read_text())
        rule_id = int(doc.get("rule_id") or path.stem)
        family = path.parent.name
        for test in doc.get("tests", []):
            test_id = test.get("test_id")
            for n, stage in enumerate(test.get("stages", [])):
                stage = stage.get("stage", stage)
                inp, out = stage.get("input", {}), stage.get("output", {})
                log = out.get("log", {}) or {}
                expect, forbid = ids_of(log, "expect_ids"), ids_of(log, "no_expect_ids")
                case = {"file": str(path.relative_to(args.tests_dir)), "rule": rule_id,
                        "test": test_id, "stage": n, "expect": sorted(expect),
                        "forbid": sorted(forbid)}
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
                while not lines.empty():
                    lines.get_nowait()
                status = send((args.host, args.port), build_request(inp, args.host_header))
                case["status"] = status
                rec = next_line_for(lines, inp)
                if rec is None:
                    case.update(result="unsupported",
                                reason="no access-log line: rejected before the WAF")
                    continue
                # Kept for auditing the attribution: the sent and logged URIs.
                case["uri"], case["logged_uri"] = str(inp.get("uri", "")), rec.get("uri")
                listed = {x for x in str(rec.get("rule_ids") or "").split(",") if x}
                total = int(rec.get("rule_matches") or 0)
                # The longer list only matters when it could change the answer:
                # an expected rule missing, or a forbidden one possibly unlisted.
                if (total > len(listed) and waf_proc is not None
                        and (expect - {int(x) for x in listed if x.isdigit()} or forbid)):
                    deadline = time.monotonic() + LOG_WAIT_SECS
                    while rec.get("request_id") not in waf_ids and time.monotonic() < deadline:
                        time.sleep(0.02)
                    listed |= waf_ids.pop(rec.get("request_id"), set())
                fired = {int(x) for x in listed if x.isdigit()}
                case["fired"] = sorted(fired)
                case["matched_total"] = total
                missing, unwanted = expect - fired, forbid & fired
                # Rule IDs (not ML and other engines' labels) beyond what the
                # logs list: an expected one may be among them, a forbidden
                # one may be hiding there.
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
                    case["status_ok"] = status in allowed
    proc.terminate()
    if waf_proc is not None:
        waf_proc.terminate()

    totals = Counter(c["result"] for c in cases)
    reasons = Counter(c.get("reason") for c in cases if c["result"] == "unsupported")
    by_family = defaultdict(Counter)
    for c in cases:
        by_family[c["file"].split("/")[0]][c["result"]] += 1
    print(f"{len(cases)} cases: " + ", ".join(f"{k} {v}" for k, v in sorted(totals.items())))
    for reason, n in reasons.most_common():
        print(f"  unsupported: {n:5d}  {reason}")
    status_checked = [c for c in cases if "status_ok" in c]
    if status_checked:
        print(f"  status expectations: {sum(c['status_ok'] for c in status_checked)}"
              f" of {len(status_checked)} as CRS expects (reported, not scored)")
    print()
    for fam in sorted(by_family):
        t = by_family[fam]
        print(f"{fam:52s} pass {t['pass']:4d}  fail {t['fail']:4d}  unsupported {t['unsupported']:4d}")
    fails = [c for c in cases if c["result"] == "fail"]
    if fails:
        print("\nfailing rules:")
        per_rule = Counter(c["rule"] for c in fails)
        for rule, n in sorted(per_rule.items()):
            print(f"  {rule}: {n} case(s)")
    if args.json:
        Path(args.json).write_text(json.dumps(cases, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
