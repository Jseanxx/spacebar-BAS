from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import argparse
import json
import mimetypes
import time


class SupportHandler(BaseHTTPRequestHandler):
    server_version = "SpacebarBASSupport/0.1"

    def log_message(self, fmt, *args):
        message = "%s - - [%s] %s\n" % (
            self.client_address[0],
            self.log_date_time_string(),
            fmt % args,
        )
        self.server.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.server.log_path.open("a", encoding="utf-8") as file:
            file.write(message)

    def do_GET(self):
        if self.path in ("/health", "/healthz"):
            self.send_json({"status": "ok", "role": self.server.role})
            return

        relative = self.path.lstrip("/") or self.server.default_file
        target = (self.server.root_dir / relative).resolve()

        try:
            target.relative_to(self.server.root_dir.resolve())
        except ValueError:
            self.send_error(403, "path is outside root")
            return

        if not target.exists() or not target.is_file():
            self.send_error(404, "file not found")
            return

        data = target.read_bytes()
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length)
        self.server.upload_dir.mkdir(parents=True, exist_ok=True)
        name = f"upload-{int(time.time())}-{self.client_address[0].replace('.', '-')}.bin"
        path = self.server.upload_dir / name
        path.write_bytes(body)
        self.send_json({
            "status": "saved",
            "bytes": len(body),
            "path": str(path),
        })

    def send_json(self, payload):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    parser = argparse.ArgumentParser(description="SB-AD attacker-side support server for BAS file transfer and upload tests.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--root", default="/tmp/spacebar-bas-support")
    parser.add_argument("--upload-dir", default="/tmp/spacebar-bas-support/uploads")
    parser.add_argument("--log", default="/tmp/spacebar-bas-support/support-server.log")
    parser.add_argument("--role", default="support")
    parser.add_argument("--default-file", default="bas_t1105_probe.txt")
    args = parser.parse_args()

    root_dir = Path(args.root)
    root_dir.mkdir(parents=True, exist_ok=True)
    default_file = root_dir / args.default_file
    if not default_file.exists():
        default_file.write_text("Spacebar BAS benign T1105 probe file.\n", encoding="utf-8")

    server = ThreadingHTTPServer((args.host, args.port), SupportHandler)
    server.root_dir = root_dir
    server.upload_dir = Path(args.upload_dir)
    server.log_path = Path(args.log)
    server.role = args.role
    server.default_file = args.default_file

    print(f"[+] SB-AD support server listening on {args.host}:{args.port} role={args.role}")
    print(f"[+] root={server.root_dir} upload_dir={server.upload_dir}")
    server.serve_forever()


if __name__ == "__main__":
    main()
