"""Minimal test target for zap-proxy: plain http.server with no security
headers (so passive rules 10038 fire). Serves /, /a, /x (link graph)."""
import http.server
import threading

HTML_INDEX = b'<html><body><a href="/a">a</a><a href="/x?q=1">x</a></body></html>'
HTML_A = b'<html><body><a href="/">home</a></body></html>'
HTML_X = b'<html><body>query page</body></html>'


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/a"):
            body = HTML_A
        elif self.path.startswith("/x"):
            body = HTML_X
        else:
            body = HTML_INDEX
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass


def serve(host="127.0.0.1", port=8765):
    srv = http.server.ThreadingHTTPServer((host, port), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


if __name__ == "__main__":
    srv = serve()
    print("listening on http://127.0.0.1:8765")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
