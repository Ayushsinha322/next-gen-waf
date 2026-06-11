#!/usr/bin/env python3
"""Fake customer website for WAF troubleshooting practice.
Serves a simple HTML page on port 9999 with a login form — perfect for testing WAF attacks.
"""
import http.server
import socketserver
import sys
import os

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9999

HTML = b"""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Acme Corp - Customer Portal</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 80px auto; text-align: center; }
        h1 { color: #2c3e50; }
        form { background: #ecf0f1; padding: 24px; border-radius: 8px; }
        input { width: 90%; padding: 10px; margin: 8px 0; border: 1px solid #ccc; border-radius: 4px; }
        button { background: #27ae60; color: white; padding: 10px 24px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #219a52; }
    </style>
</head>
<body>
    <h1>Acme Corp - Customer Portal</h1>
    <p>Welcome! Please login to access your account.</p>
    <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Username" />
        <input type="password" name="password" placeholder="Password" />
        <button type="submit">Login</button>
    </form>
    <p style="margin-top: 20px; font-size: 12px; color: #7f8c8d;">
        Server: FakeCustomerServer v1.0
    </p>
</body>
</html>
"""

class FakeSite(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(HTML)
        elif self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK\n")
        elif self.path == "/api/users":
            # Deliberate vulnerable endpoint — returns all users
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"users":[{"id":1,"name":"admin"},{"id":2,"name":"john"}]}\n')
        elif self.path == "/search":
            # Deliberate XSS-vulnerable endpoint — reflects the query param
            import urllib.parse
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            query = params.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            # dangerously echoes user input without sanitization
            self.wfile.write(f"<html><body>Results for: {query}</body></html>".encode())
        elif self.path == "/status":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Acme Portal is running.\n")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found\n")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""

        if self.path == "/login":
            import urllib.parse
            params = urllib.parse.parse_qs(body.decode())
            user = params.get("username", [""])[0]
            pw = params.get("password", [""])[0]

            # Deliberate SQL injection vulnerable
            if user == "admin" and pw == "admin123":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok","message":"Welcome admin!"}\n')
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"fail","message":"Invalid credentials"}\n')
        elif self.path == "/eval":
            # Deliberate RCE endpoint
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"Received: {body.decode()}\n".encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found\n")

    def log_message(self, format, *args):
        # Quiet logging
        print(f"[fake-site] {args[0]}", flush=True)

if __name__ == "__main__":
    print(f"[fake-site] Starting Acme Corp Customer Portal on :{PORT}", flush=True)
    with socketserver.TCPServer(("0.0.0.0", PORT), FakeSite) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[fake-site] Shutting down.", flush=True)