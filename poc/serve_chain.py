#!/usr/bin/env python3
"""PS4 FW 13.52 browser-chain server.

Serves the chain_1352.js exploit bundle to the PS4 built-in browser and
captures the chain's progress telemetry. chain_1352.js posts every mark()
through two channels:

    GET /log?m=<b64? no -- raw urlencoded>[TAG] detail...
    POST /t                body: PS4-S10&tag=<TAG>&detail=<detail>

(detail is raw urlencoded text). Either channel that keeps coming back with
404/501 means the chain is blind-fighting toward a waypoint we never see.

Static files (core.js, mem.js, int64.js, ps4_offsets.js, rpc_worker.js,
patches/*.bin, payload.bin) are served from this directory with permissive
CORS. Run it with the PS4 pointed at http://<termux-ip>:8080/run_1352.html.
"""
import http.server
import socketserver
import urllib.parse
import os
import sys
import time
import socket
from http.server import ThreadingHTTPServer

PORT = int(os.environ.get("PS4_PORT", "8080"))
DIR = os.path.dirname(os.path.abspath(__file__))
LOG = os.environ.get("PS4_LOG",
    "/data/data/com.termux/files/home/chain_1352_live.log")

os.chdir(DIR)

_SEP = " | "

# Short links -- the PS4 browser URL bar is painful to type in, so every
# probe gets a one-character alias. 302 so the query string + JS identical.
SHORT = {
    "/e": "/run_sb588d.html?probe=evscan",          # event-namespace scan
    "/x": "/run_sb588d.html?rcl=1&cred=reuid",      # full chain, reuid cred
    "/s": "/run_sb588d.html?stop=beforedouble",     # arm-only + stop
    "/m": "/run_sb588d.html?probe=mu",              # auto/forced slot matrix
    "/n": "/run_sb588d.html?probe=netevent",        # slot-free decisive
    "/c": "/run_sb588d.html?probe=cs",              # cred-swap sweep
    "/t": "/run_sb588d.html?probe=ev10",            # live-event 0x20000010
    "/v": "/run_sb588k.html?probe=verbatim",       # verbatim chain, spray=iovSs[0] + errno diag
    "/g": "/",                                       # go home
}


def _log_line(tag, detail, chan):
    ts = time.strftime("%H:%M:%S")
    if tag.startswith("["):
        return f"{ts} {chan} {tag} {detail}\n"
    return f"{ts} {chan} [{tag}] {detail}\n"


class Handler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _write(self, body=b"ok\n", ctype="text/plain; charset=utf-8",
               code=200, cors=True):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-cache")
        if cors:
            self._cors()
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _append(self, line):
        try:
            with open(LOG, "a") as f:
                f.write(line)
        except OSError as e:
            print(f"[WARN] cannot append log: {e}", flush=True)
        print(line.rstrip("\n"), flush=True)

    def do_OPTIONS(self):
        self._write(code=204)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        if parsed.path in SHORT:
            target = SHORT[parsed.path]
            if qs:
                extra = "&".join(k + "=" + v[0] for k, v in qs.items())
                target += ("&" if "?" in target else "?") + extra
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            self._append(_log_line("REDIRECT", f"{parsed.path} -> {target}", "L>"))
            return
        if parsed.path == "/log":
            msg = qs.get("m", [""])[0]
            self._append(_log_line("GET", msg, "L>"))
            self._write()
            return
        if parsed.path == "/out":          # tail of the live log for Termux
            try:
                with open(LOG, "r") as f:
                    body = f.read().encode("utf-8", "replace")
            except OSError:
                body = b"(no log yet)"
            self._write(body, "text/plain; charset=utf-8")
            return
        if parsed.path == "/clear":
            try:
                open(LOG, "w").close()
            except OSError:
                pass
            self._write(b"cleared\n")
            return
        # static files: SimpleHTTPRequestHandler (logged, cached no)
        super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/t":
            n = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(n).decode("utf-8", "replace")
            fields = urllib.parse.parse_qs(body)
            tag = fields.get("tag", [""])[0]
            det = fields.get("detail", [""])[0]
            if not tag and fields.get("PS4-S10", []):
                tag = fields.get("PS4-S10", [""])[0]
                if len(fields.get("tag", [])): tag = fields.get("tag", [""])[0]
            self._append(_log_line(tag, det, "P>"))
            self._write()
            return
        self._write(b"not found\n", code=404)
        return

    def log_message(self, fmt, *args):
        st = fmt % args
        print(st, flush=True)

    def guess_type(self, path):
        if path.endswith(".js"):
            return "application/javascript; charset=utf-8"
        if path.endswith(".html") or path.endswith(".htm"):
            return "text/html; charset=utf-8"
        if path.endswith(".bin"):
            return "application/octet-stream"
        return http.server.SimpleHTTPRequestHandler.guess_type(self, path)

    def end_headers(self):
        # keep static responses no-cache too (browser re-fetches chain each run)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        try:
            http.server.SimpleHTTPRequestHandler.end_headers(self)
        except (ConnectionError, BrokenPipeError, OSError):
            pass

    def copyfile(self, source, outputfile):
        try:
            super().copyfile(source, outputfile)
        except (BrokenPipeError, ConnectionError):
            pass


if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    ThreadingHTTPServer.daemon_threads = True
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    url = socket.gethostbyname(socket.gethostname())
    try:
        url = socket.gethostbyname_ex(socket.gethostname())[2][0]
    except Exception:
        pass
    print(f"chain server http://0.0.0.0:{PORT}/ (dir {DIR})", flush=True)
    print(f"log -> {LOG}", flush=True)
    print("browser -> http://<ps4-ip>:{port}/run_1352.html"
          .format(port=PORT), flush=True)
    print("tail:  curl http://127.0.0.1:{port}/out  | "
          "clear: curl http://127.0.0.1:{port}/clear".format(port=PORT),
          flush=True)
    httpd.serve_forever()