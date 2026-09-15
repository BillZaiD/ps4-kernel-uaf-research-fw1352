#!/usr/bin/env python3
"""
Live-reload server for PS4 FW 13.52 kernel research.
Server dynamically concatenates JS files (stripping import/export) on each request.
When any source file changes, PS4 browser auto-reloads via SSE.

Usage:
    python3 serve_live.py [port]    # Default: 8084

Workflow:
    1. Open http://<termux_ip>:8084/ on PS4
    2. Edit any file in src/ on Termux
    3. PS4 auto-reloads — no manual refresh needed
    4. View results at http://<termux_ip>:8084/results

Edit these files live:
    src/chain_s434.js   — probe logic (main file to edit)
    src/core.js         — JSC primitive
    src/mem.js          — window.p installation
    src/int64.js        — int64 class
    src/ps4_offsets.js  — offset tables
    run_s434.html       — page template (static)
"""
import os, sys, re, json, time, datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote, urlparse, parse_qs
from pathlib import Path

DIR = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(DIR, "src")
LOG = os.path.join(DIR, "results", "probe.log")
os.makedirs(os.path.join(DIR, "results"), exist_ok=True)

_reload_counter = 0
_file_mtimes = {}


def _read(fname):
    with open(fname, "r") as f:
        return f.read()


def _strip_imports(code):
    code = re.sub(r'^import\s+\{[^}]*\}\s+from\s+[\'"][^\'"]*[\'"];?\s*$', '', code, flags=re.MULTILINE | re.DOTALL)
    code = re.sub(r'^import\s+\w+\s+from\s+[\'"][^\'"]*[\'"];?\s*$', '', code, flags=re.MULTILINE)
    code = re.sub(r'^import\s+.*$', '', code, flags=re.MULTILINE)
    return code


def _strip_exports(code):
    code = re.sub(r'^export\s+\{[^}]*\};?\s*$', '', code, flags=re.MULTILINE | re.DOTALL)
    code = re.sub(r'^export\s+default\s+', '', code, flags=re.MULTILINE)
    code = re.sub(r'^export\s+(?:async\s+)?function\s+', 'function ', code, flags=re.MULTILINE)
    code = re.sub(r'^export\s+const\s+', 'const ', code, flags=re.MULTILINE)
    return code


def _build_chain_js():
    """Dynamically build combined JS from source files."""
    parts = []
    for fname in ["int64.js", "core.js", "mem.js", "ps4_offsets.js", "chain_s434.js"]:
        fpath = os.path.join(SRC, fname)
        if not os.path.isfile(fpath):
            continue
        code = _read(fpath)
        code = _strip_exports(code)
        code = _strip_imports(code)
        parts.append(f"// === {fname} ===\n{code}")
    return "\n\n".join(parts)


def _scan_mtimes():
    """Scan all source files and record their mtimes."""
    global _file_mtimes
    for ext in ("*.js", "*.html", "*.py"):
        for f in Path(DIR).rglob(ext):
            rel = str(f.relative_to(DIR))
            try:
                _file_mtimes[rel] = f.stat().st_mtime
            except OSError:
                pass


def _check_changes():
    """Check if any source file changed since last scan."""
    global _reload_counter, _file_mtimes
    changed = False
    for ext in ("*.js", "*.html", "*.py"):
        for f in Path(DIR).rglob(ext):
            rel = str(f.relative_to(DIR))
            if rel == "run_s434.html":
                continue  # don't auto-reload for template changes
            try:
                mt = f.stat().st_mtime
            except OSError:
                continue
            old = _file_mtimes.get(rel)
            if old is not None and mt > old:
                changed = True
            _file_mtimes[rel] = mt
    if changed:
        _reload_counter += 1
        print(f"  [{datetime.datetime.now():%H:%M:%S}] Files changed → reload #{_reload_counter}")
    return changed


MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".log": "text/plain; charset=utf-8",
    ".py": "text/plain; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
}

CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
    "Access-Control-Allow-Headers": "*",
}


class LiveHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _cors(self):
        for k, v in CORS.items():
            self.send_header(k, v)

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)

        # === SSE: live reload stream ===
        if path == "/events":
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()

            try:
                self.wfile.write(f"event: init\ndata: {json.dumps({'token': _reload_counter})}\n\n".encode())
                self.wfile.flush()
                while True:
                    time.sleep(1)
                    try:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        break
                    _check_changes()
                    if _reload_counter > 0:
                        try:
                            self.wfile.write(f"event: reload\ndata: {json.dumps({'token': _reload_counter})}\n\n".encode())
                            self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError):
                            break
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        # === Dynamically built combined JS ===
        if path == "/chain_all.js":
            code = _build_chain_js()
            data = code.encode()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(data)
            return

        # === Telemetry log endpoint ===
        if path == "/log":
            msg = ""
            qs = self.path.split("?", 1)[1] if "?" in self.path else ""
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

        # === Results viewer ===
        if path == "/results":
            try:
                with open(LOG, "rb") as f:
                    data = f.read()
            except Exception:
                data = b"(no results yet)"
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(data)
            return

        # === Clear results ===
        if path == "/clear":
            with open(LOG, "w") as f:
                pass
            self.send_response(200)
            self._cors()
            self.end_headers()
            self.wfile.write(b"cleared")
            return

        # === Status ===
        if path == "/status":
            _check_changes()
            info = {"reload_token": _reload_counter, "files": len(_file_mtimes)}
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(info, indent=2).encode())
            return

        # === Static files ===
        if path in ("/", "/index.html"):
            fpath = os.path.join(DIR, "run_s434.html")
        else:
            fpath = os.path.join(DIR, path.lstrip("/"))

        if not os.path.isfile(fpath):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(f"404: {path}".encode())
            return

        ext = os.path.splitext(fpath)[1]
        ct = MIME.get(ext, "application/octet-stream")

        with open(fpath, "rb") as f:
            data = f.read()

        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8084
    _scan_mtimes()
    srv = HTTPServer(("0.0.0.0", port), LiveHandler)
    print()
    print("  ╔═══════════════════════════════════════════════════════╗")
    print("  ║  PS4 FW 13.52 — Live Kernel Research Server           ║")
    print("  ╠═══════════════════════════════════════════════════════╣")
    print(f"  ║  PS4 Browser:   http://192.168.100.2:{port}/             ║")
    print(f"  ║  Results:       http://192.168.100.2:{port}/results      ║")
    print(f"  ║  Live reload:   watching {len(_file_mtimes)} source files          ║")
    print("  ╚═══════════════════════════════════════════════════════╝")
    print()
    print("  Edit src/*.js on Termux → PS4 auto-reloads instantly")
    print("  Ctrl+C to stop")
    print()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped")
