import atexit
import http.server
import os
import secrets
import urllib.parse
from http.cookies import SimpleCookie
import atexit

# Real localhost port the bank actually listens on
BANK_HTTP_PORT = 18003

USERS = {
    "sabrina": "PleaseComeBack",
    "jensen":  "iceflower",
    "attacker": "12345678",
}

BALANCES = {
    "sabrina":  50_000,
    "jensen":   12_500,
    "attacker": 0,
}

SESSIONS = {}  # session_id -> username


def render_page(title, body):
    return (
        f"<!doctype html><html><head><title>{title}</title></head>"
        f"<body><h1>{title}</h1>{body}</body></html>"
    ).encode("utf-8")


class BankHandler(http.server.BaseHTTPRequestHandler):
    server_version = "FakeBank/1.0"

    def log_message(self, fmt, *args):
        # quiet
        pass

    # ---------- helpers ----------
    def _read_form(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        return urllib.parse.parse_qs(body.decode("utf-8", errors="replace")), body

    def _current_user(self):
        ck = SimpleCookie()
        ck.load(self.headers.get("Cookie", ""))
        sid = ck["sid"].value if "sid" in ck else None
        return SESSIONS.get(sid), sid

    def _send_text(self, status, text, set_cookie=None, content_type="text/plain"):
        data = text.encode("utf-8") if isinstance(text, str) else text
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()
        self.wfile.write(data)
        print(f"[bank] {self.command} {self.path} -> {status}", flush=True)

    # ---------- routes ----------
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            user, _ = self._current_user()
            if user is None:
                return self._send_text(200, "Welcome to FakeBank. Please /login.")
            return self._send_text(
                200, f"Hello {user}. Your balance is ${BALANCES.get(user, 0)}."
            )
        if path == "/balance":
            user, _ = self._current_user()
            if user is None:
                return self._send_text(401, "Not logged in.")
            return self._send_text(200, f"{user}: ${BALANCES.get(user, 0)}")
        return self._send_text(404, "Not found.")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        form, _ = self._read_form()
        if path == "/login":
            user = (form.get("username", [""])[0] or "").lower()
            pw = form.get("password", [""])[0]
            if USERS.get(user) != pw:
                return self._send_text(403, "Invalid credentials.")
            sid = secrets.token_hex(8)
            SESSIONS[sid] = user
            return self._send_text(
                200, f"Logged in as {user}.",
                set_cookie=f"sid={sid}; Path=/; HttpOnly",
            )
        if path == "/transfer":
            user, _ = self._current_user()
            if user is None:
                return self._send_text(401, "Not logged in.")
            src = (form.get("from", [""])[0] or "").lower()
            dst = (form.get("to", [""])[0] or "").lower()
            amt = int(form.get("amount", ["0"])[0] or "0")
            if src != user:
                return self._send_text(403, "Cannot transfer from another account.")
            if dst not in BALANCES:
                return self._send_text(400, f"Unknown recipient: {dst}.")
            if BALANCES[src] < amt or amt <= 0:
                return self._send_text(400, "Insufficient funds.")
            BALANCES[src] -= amt
            BALANCES[dst] += amt
            return self._send_text(
                200, f'{src} SENT ${amt} TO "{dst}"'
            )
        if path == "/logout":
            _, sid = self._current_user()
            if sid:
                SESSIONS.pop(sid, None)
            return self._send_text(
                200, "Logged out.",
                set_cookie="sid=; Path=/; Max-Age=0",
            )
        return self._send_text(404, "Not found.")


def main():
    from network import config
    import signal
    print(f"[bank] starting balances: {BALANCES}", flush=True)
    def _on_exit(*_):
        print(f"[bank] final balances: {BALANCES}", flush=True)
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, _on_exit)
    signal.signal(signal.SIGINT, _on_exit)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", BANK_HTTP_PORT), BankHandler)
    print(f"[bank] listening at {config.BANK_IP}", flush=True)
    srv.serve_forever()

if __name__ == "__main__":
    main()
