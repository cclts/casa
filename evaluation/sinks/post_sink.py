#!/usr/bin/env python3
import argparse
import datetime as dt
import http.server
import json
import pathlib
import socketserver


class Handler(http.server.BaseHTTPRequestHandler):
    sink_dir = pathlib.Path(".")

    def _write_record(self, body: bytes) -> None:
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        record = {
            "timestamp": now,
            "client": self.client_address[0],
            "path": self.path,
            "headers": dict(self.headers),
            "body_utf8": body.decode("utf-8", errors="replace"),
        }
        out = self.sink_dir / "requests.jsonl"
        with out.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self._write_record(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok\n")

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok\n")

    def log_message(self, fmt, *args):
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18000)
    parser.add_argument("--out-dir", default="evaluation/results/sink")
    args = parser.parse_args()

    sink_dir = pathlib.Path(args.out_dir)
    sink_dir.mkdir(parents=True, exist_ok=True)
    Handler.sink_dir = sink_dir

    with socketserver.TCPServer(("0.0.0.0", args.port), Handler) as httpd:
        print(f"POST sink listening on 0.0.0.0:{args.port}")
        print(f"Writing requests to {sink_dir / 'requests.jsonl'}")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
