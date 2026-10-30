from __future__ import annotations

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/blocked"):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"blocked")
            return
        return super().do_GET()

    def log_message(self, format, *args):
        pass  # silence logs in demo


if __name__ == "__main__":
    root = Path(__file__).parent / "mockweb"
    if not root.exists():
        print(f"Mock web not found at {root}. Run: python demo/make_mockweb.py")
        raise SystemExit(1)
    server = ThreadingHTTPServer(
        ("127.0.0.1", 8765),
        lambda *a, **k: Handler(*a, directory=str(root), **k),
    )
    print(f"Serving {root} on http://127.0.0.1:8765")
    server.serve_forever()

