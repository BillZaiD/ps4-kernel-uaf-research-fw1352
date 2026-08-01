#!/usr/bin/env python3
import http.server
import socketserver
import socket
import os
import sys
import json
import urllib.parse
import threading
import time

PORT = 8080
DIR = '/data/data/com.termux/files/home/PS4-Kernel-Research-FW1352/poc'
LOG = '/data/data/com.termux/files/home/cve_test_log.txt'
PS4_IP = '192.168.100.61'
PS4_PORT = 9026

os.chdir(DIR)

# Command queue - server can send commands to browser
commands = []
results = []

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path == '/log':
            msg = params.get('m', [''])[0]
            with open(LOG, 'a') as f:
                f.write(msg + '\n')
            print(f'[PS4] {msg}', flush=True)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'ok')
            return

        if path == '/readlog':
            try:
                with open(LOG, 'r') as f:
                    content = f.read()
            except:
                content = '(no logs yet)'
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(content.encode())
            return

        if path == '/clearlog':
            with open(LOG, 'w') as f:
                f.write('')
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'cleared')
            return

        # Browser polls for commands from server
        if path == '/poll':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            if commands:
                cmd = commands.pop(0)
                self.wfile.write(json.dumps(cmd).encode())
                print(f'[CMD] Sent to PS4: {cmd}', flush=True)
            else:
                self.wfile.write(b'null')
            return

        # Browser sends results back
        if path == '/result':
            result = params.get('r', [''])[0]
            tag = params.get('tag', [''])[0]
            results.append({'tag': tag, 'result': result, 'time': time.time()})
            with open(LOG, 'a') as f:
                f.write(f'[RESULT:{tag}] {result}\n')
            print(f'[RESULT:{tag}] {result}', flush=True)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'ok')
            return

        # Browser sends binary data (for heap dumps, etc.)
        if path == '/data':
            data = params.get('d', [''])[0]
            tag = params.get('tag', [''])[0]
            fname = f'/data/data/com.termux/files/home/ps4_data_{tag}_{int(time.time())}.bin'
            with open(fname, 'wb') as f:
                f.write(data.encode('latin-1'))
            print(f'[DATA:{tag}] Saved {len(data)} bytes to {fname}', flush=True)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'ok')
            return

        # Read results summary
        if path == '/results':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(results[-50:]).encode())
            return

        # Enqueue a command (from control script on Termux)
        if path == '/enqueue':
            action = params.get('action', [''])[0]
            args_str = params.get('args', ['[]'])[0]
            try:
                args = json.loads(args_str)
            except:
                args = []
            commands.append({'action': action, 'args': args})
            print(f'[ENQUEUE] {action} {args}', flush=True)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(b'queued')
            return

        # View command queue
        if path == '/queue':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(commands).encode())
            return

        super().do_GET()

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == '/exec_lua':
            # Send Lua script to PS4 Lua loader
            try:
                lua_code = body.decode('utf-8')
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((PS4_IP, PS4_PORT))
                import struct
                data = lua_code.encode('utf-8')
                s.send(struct.pack('<Q', len(data)) + data)
                
                # Try to read response
                response = b''
                try:
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                except socket.timeout:
                    pass
                s.close()
                
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(response)
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'text/plain')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(str(e).encode())
            return

        self.send_response(404)
        self.end_headers()

    def guess_type(self, path):
        if path.endswith('.html') or path.endswith('.htm'):
            return 'text/html; charset=utf-8'
        if path.endswith('.json'):
            return 'application/json'
        return http.server.SimpleHTTPRequestHandler.guess_type(self, path)

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-cache')
        http.server.SimpleHTTPRequestHandler.end_headers(self)

    def log_message(self, format, *args):
        print('[REQ] ' + (format % args), flush=True)

# Clear old log
with open(LOG, 'w') as f:
    f.write('')

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(('0.0.0.0', PORT), Handler) as httpd:
    print(f'Serving on http://0.0.0.0:{PORT}/', flush=True)
    print(f'PS4 Lua loader: {PS4_IP}:{PS4_PORT}', flush=True)
    print('Commands:', flush=True)
    print('  GET /poll  - browser polls for commands', flush=True)
    print('  GET /result?tag=X&data=Y - browser sends results', flush=True)
    print('  POST /exec_lua - send Lua to PS4 loader', flush=True)
    print('  GET /results - view all results', flush=True)
    print('  GET /readlog - view log', flush=True)
    httpd.serve_forever()
