#!/usr/bin/env python3
"""Tiny HTTPS reverse proxy for the local CI end-to-end test.

Terminates TLS for `localhost:<https_port>` with the test certificate and
forwards each request to the plain-HTTP starforged listener. The
`starforge-sandboxd` egress proxy trusts the test CA through
`--egress-upstream-ca`, so the sandbox's TLS verification exercises the
same path as a private HTTPS origin.

Usage: https_proxy.py SERVER_PORT HTTPS_PORT CERT KEY
"""

import http.client
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVER_PORT = int(sys.argv[1])
HTTPS_PORT = int(sys.argv[2])
CERT = sys.argv[3]
KEY = sys.argv[4]


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _forward(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in ("connection", "content-length")
        }
        conn = http.client.HTTPConnection("127.0.0.1", SERVER_PORT, timeout=60)
        conn.request(self.command, self.path, body=body, headers=headers)
        response = conn.getresponse()
        data = response.read()
        self.send_response(response.status, response.reason)
        for key, value in response.getheaders():
            if key.lower() not in ("connection", "content-length", "transfer-encoding"):
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        conn.close()

    do_GET = _forward
    do_POST = _forward
    do_PUT = _forward
    do_DELETE = _forward
    do_HEAD = _forward

    def log_message(self, fmt, *args):
        sys.stderr.write("https-proxy: " + fmt % args + "\n")


def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT, KEY)
    server = ThreadingHTTPServer(("127.0.0.1", HTTPS_PORT), Proxy)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f"https proxy on 127.0.0.1:{HTTPS_PORT} -> 127.0.0.1:{SERVER_PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
