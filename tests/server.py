import http.server
import sys

class ServerClass(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response_only(200)
        self.end_headers()

if __name__ == '__main__':
    server_address = ('127.0.0.1', int(sys.argv[1]))
    httpd = http.server.HTTPServer(server_address, ServerClass)
    print('HTTP server started', flush=True)
    httpd.serve_forever()
