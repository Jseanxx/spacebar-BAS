#!/usr/bin/env python3
import argparse
import http.server
import urllib.error
import urllib.request


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


class ApiForwardHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def do_PUT(self):
        self.forward()

    def do_PATCH(self):
        self.forward()

    def do_DELETE(self):
        self.forward()

    def log_message(self, fmt, *args):
        print(f"{self.client_address[0]} - {fmt % args}", flush=True)

    def forward(self):
        body = None
        content_length = int(self.headers.get("Content-Length") or "0")
        if content_length:
            body = self.rfile.read(content_length)

        forward_path = self.path
        if not (forward_path == "/api" or forward_path.startswith("/api/")):
            forward_path = "/api" + forward_path

        target_url = self.server.target_base_url.rstrip("/") + forward_path
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP_HEADERS and key.lower() != "host"
        }

        request = urllib.request.Request(
            target_url,
            data=body,
            headers=headers,
            method=self.command,
        )

        try:
            with urllib.request.urlopen(request, timeout=self.server.timeout_seconds) as response:
                response_body = response.read()
                self.send_response(response.status)
                self.send_forward_headers(response.headers, len(response_body))
                self.end_headers()
                self.wfile.write(response_body)
        except urllib.error.HTTPError as exc:
            response_body = exc.read()
            self.send_response(exc.code)
            self.send_forward_headers(exc.headers, len(response_body))
            self.end_headers()
            self.wfile.write(response_body)
        except Exception as exc:
            response_body = str(exc).encode("utf-8")
            self.send_response(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

    def send_forward_headers(self, headers, body_length):
        skipped = HOP_BY_HOP_HEADERS | {"content-length", "server", "date"}
        for key, value in headers.items():
            if key.lower() not in skipped:
                self.send_header(key, value)
        self.send_header("Content-Length", str(body_length))


class ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser(description="HTTP to HTTPS forwarder for BAS Agent API traffic.")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--target-base-url", default="https://kisia.kro.kr")
    parser.add_argument("--timeout-seconds", type=int, default=90)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.listen_host, args.listen_port), ApiForwardHandler)
    server.target_base_url = args.target_base_url
    server.timeout_seconds = args.timeout_seconds

    print(
        f"forwarding http://{args.listen_host}:{args.listen_port} -> "
        f"{args.target_base_url}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
