#!/usr/bin/env python3
"""Simple HTTP server for PS4 FW 13.52 probe — serves run_s434.html at root."""
import os, sys, json, time, datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote

DIR = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(DIR, "results", "probe.log")
os.makedirs(os.path.join(DIR, "results"), exist_ok=True)

H = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
    "Access-Control-Allow-Headers": "*",
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        try:
            with open(LOG, "a") as f:
                f.write(f"[{datetime.datetime.now():%H:%M:%S}] {fmt % args}\n")
        except Exception:
            pass

    def _cors(self):
        for k, v in H.items():
            self.send_header(k, v)

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        path = unquote(self.path.split("?")[0])
        qs = self.path.split("?", 1)[1] if "?" in self.path else ""

        # Telemetry logging endpoint
        if path == "/log":
            msg = ""
            for part in qs.split("&"):
                if part.startswith("m="):
                    msg = unquote(part[2:])
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
            try:
                with open(LOG, "a") as f:
                    f.write(f"[{datetime.datetime.now():%H:%M:%S}] {msg}\n")
            except Exception:
                pass
            return

        # Results endpoint
        if path == "/results":
            try:
                with open(LOG, "rb") as f:
                    data = f.read()
            except Exception:
                data = b"(no results yet)"
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(data)
            return

        # Clear results
        if path == "/clear":
            try:
                with open(LOG, "w") as f:
                    f.write("")
            except Exception:
                pass
            self.send_response(200)
            self._cors()
            self.end_headers()
            self.wfile.write(b"cleared")
            return

        # Serve run_s434.html at root
        if path == "/" or path == "/index.html" or path == "":
            fpath = os.path.join(DIR, "run_s434.html")
        else:
            fpath = os.path.join(DIR, path.lstrip("/"))

        if not os.path.isfile(fpath):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404")
            return

        ct = "text/html"
        if fpath.endswith(".js"):
            ct = "application/javascript"
        elif fpath.endswith(".css"):
            ct = "text/css"
        elif fpath.endswith(".log"):
            ct = "text/plain"
        elif fpath.endswith(".html"):
            ct = "text/html"

        with open(fpath, "rb") as f:
            data = f.read()
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", ct + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8084
    srv = HTTPServer(("0.0.0.0", port), Handler)
    print(f"[s434] Listening on http://0.0.0.0:{port}")
    print(f"[s434] PS4 open: http://192.168.100.2:{port}/")
    print(f"[s434] Results: http://192.168.100.2:{port}/results")
    print(f"[s434] Log file: {LOG}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[s434] Stopped")
