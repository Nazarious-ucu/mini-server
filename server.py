#!/usr/bin/env python3
import json
import os
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_FILE = "webhook_log.jsonl"
MAX_BODY_BYTES = 2 * 1024 * 1024  # 2MB


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def extract_client_ip(headers, socket_peer_ip):
    """
    Returns (real_ip, source, chain)
    - real_ip: best guess of original client IP (behind ngrok/proxy)
    - source: X-Forwarded-For / X-Real-IP / socket
    - chain: full X-Forwarded-For list (if present)
    """
    xff = headers.get("X-Forwarded-For")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[0], "X-Forwarded-For", parts

    xri = headers.get("X-Real-IP")
    if xri:
        ip = xri.strip()
        return ip, "X-Real-IP", [ip]

    return socket_peer_ip, "socket", [socket_peer_ip]


class WebhookHandler(BaseHTTPRequestHandler):
    # Silence default server logs
    def log_message(self, format, *args):
        return

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            return b"", {"error": f"Body too large: {length} bytes (limit {MAX_BODY_BYTES})"}
        return self.rfile.read(length), None

    def _build_event(self, body_bytes, body_error=None):
        # Who connected directly to us (with ngrok: usually 127.0.0.1)
        socket_peer_ip, socket_peer_port = self.client_address[0], self.client_address[1]

        # Best guess of original client on the internet (from proxy headers)
        real_ip, real_ip_source, xff_chain = extract_client_ip(self.headers, socket_peer_ip)

        # Local interface/port the connection reached (with ngrok: often 127.0.0.1:8080)
        try:
            local_ip, local_port = self.connection.getsockname()[:2]
        except Exception:
            local_ip, local_port = None, None

        # Try JSON decode (optional)
        parsed_json = None
        json_error = None
        if body_bytes:
            try:
                parsed_json = json.loads(body_bytes.decode("utf-8"))
            except Exception as e:
                json_error = str(e)

        return {
            "ts": now_iso(),
            "method": self.command,
            "path": self.path,

            # Network / IP info (the stuff you care about)
            "socket_peer_ip": socket_peer_ip,
            "socket_peer_port": socket_peer_port,
            "real_client_ip": real_ip,
            "real_client_ip_source": real_ip_source,
            "xff_chain": xff_chain,
            "local_ip": local_ip,
            "local_port": local_port,

            # Proxy-related headers (useful for debugging)
            "forwarded": self.headers.get("Forwarded"),
            "x_forwarded_for": self.headers.get("X-Forwarded-For"),
            "x_forwarded_proto": self.headers.get("X-Forwarded-Proto"),
            "x_forwarded_host": self.headers.get("X-Forwarded-Host"),
            "x_real_ip": self.headers.get("X-Real-IP"),

            # Request metadata
            "content_type": self.headers.get("Content-Type"),
            "content_length": self.headers.get("Content-Length"),
            "user_agent": self.headers.get("User-Agent"),

            # All headers
            "headers": {k: v for k, v in self.headers.items()},

            # Body
            "body_utf8": body_bytes.decode("utf-8", errors="replace") if body_bytes else "",
            "json": parsed_json,
            "json_error": json_error,
            "body_error": body_error,
        }

    def _log_event(self, event):
        line = json.dumps(event, ensure_ascii=False)
        print(line)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def do_GET(self):
        # Healthcheck
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"ok\n")

    def do_POST(self):
        body, err = self._read_body()
        event = self._build_event(body, body_error=err)
        self._log_event(event)

        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    # Optional: accept other webhook methods too
    def do_PUT(self): self.do_POST()
    def do_PATCH(self): self.do_POST()


if __name__ == "__main__":
    host = "0.0.0.0"
    port = int(os.getenv("PORT", "8080"))
    server = ThreadingHTTPServer((host, port), WebhookHandler)
    print(f"Listening on http://{host}:{port}  (log file: {LOG_FILE})")
    server.serve_forever()
