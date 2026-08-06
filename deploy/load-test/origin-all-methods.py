#!/usr/bin/env python3
"""All-methods 200 origin for FAIR WAF detection benchmarking.

Why this exists: a static origin (e.g. nginx:alpine serving files) returns 405
to benign POST/PUT/DELETE because static files only allow GET. GoTestWAF cannot
classify a 405 as blocked-or-passed, so it drops those requests from the score
denominator. The result is a CONFOUNDED benchmark:
  * bypassed non-GET *attacks* vanish as 405  -> attack-detection (TP) INFLATED
  * allowed non-GET *benign* requests vanish as 405 -> benign-allow (TN) DEFLATED

This origin returns 200 for EVERY method and path, so block/pass is decided
purely by the WAF (403 = blocked, anything else = allowed). Use it as the
upstream whenever measuring detection/false-positive rates.

Usage:  python3 origin-all-methods.py [port]   (default 18090)
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self):
        # Drain any request body so keep-alive connections stay in sync.
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            try:
                self.rfile.read(length)
            except Exception:
                pass
        body = b"<html><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        self._respond()

    do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = do_GET

    def log_message(self, *args):
        pass  # quiet


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18090
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
