#!/usr/bin/env python3
"""Turn a ModSecurity JSON audit log into the two logs crs-regression.py reads,
so the same runner and the same CRS suite run against a reference engine.

    docker logs -f --since 1s <modsec-container> \\
        | modsec-audit-adapter.py requests.jsonl waf.jsonl

Reads ModSecurity v2 JSON audit entries (MODSEC_AUDIT_LOG_FORMAT=JSON, parts
including A, B and H) on stdin. For each transaction it appends:

  requests.jsonl  a data-plane style access line — `message: "request"`, the
                  method and target from the request line, the transaction ID as
                  `request_id`, EVERY rule ID the messages name as `rule_ids`,
                  and their count as `rule_matches` (nothing is truncated here)
  waf.jsonl       a waf.log style line — the request ID, the rules, and the
                  request headers, so the runner checks its marker header

Then: crs-regression.py SUITE --port <modsec port> --dp-log requests.jsonl
--waf-log waf.jsonl ... — the reference's results, case by case, in the same
form as the product's.

The reference is set up as CRS's own CI does (owasp/modsecurity-crs image,
DetectionOnly, BLOCKING/DETECTION_PARANOIA=4, the suite's setup values) but
without the test-marker rule; see
deploy/load-test/crs-regression-reference.sh.
"""

import json
import re
import sys

ID = re.compile(r'\[id "(\d+)"\]')


def main():
    requests_path, waf_path = sys.argv[1], sys.argv[2]
    with open(requests_path, "a", buffering=1) as requests, open(waf_path, "a", buffering=1) as waf:
        for line in sys.stdin:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            tx = entry.get("transaction") or {}
            req = entry.get("request") or {}
            messages = (entry.get("audit_data") or {}).get("messages") or []
            ids = []
            for m in messages:
                for rid in ID.findall(m):
                    if rid not in ids:
                        ids.append(rid)
            parts = str(req.get("request_line", "")).split(" ")
            method = parts[0] if parts else ""
            uri = parts[1] if len(parts) > 1 else ""
            rid = tx.get("transaction_id", "")
            requests.write(json.dumps({"fields": {
                "message": "request", "method": method, "uri": uri, "request_id": rid,
                "rule_ids": ",".join(ids), "rule_matches": len(ids)}}) + "\n")
            waf.write(json.dumps({
                "request_id": rid, "rules": [{"id": i} for i in ids],
                "headers": req.get("headers") or {}}) + "\n")


if __name__ == "__main__":
    main()
