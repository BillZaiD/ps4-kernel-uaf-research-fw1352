import http.server
import socketserver
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)))

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def guess_type(self, path):
        if path.endswith('.html') or path.endswith('.htm'):
            return 'text/html; charset=utf-8'
        return http.server.SimpleHTTPRequestHandler.guess_type(self, path)
    
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        http.server.SimpleHTTPRequestHandler.end_headers(self)

with socketserver.TCPServer(('0.0.0.0', 8080), MyHandler) as httpd:
    print('Serving on http://0.0.0.0:8080/')
    httpd.serve_forever()
