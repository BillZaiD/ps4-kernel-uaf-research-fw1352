from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    
    def do_GET(self):
        if self.path == '/':
            body = b'<!DOCTYPE html><html><head><meta charset="utf-8"><title>PS4</title></head><body><h1>PS4 Test</h1><p>Browser connected.</p></body></html>'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        pass

HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
