"""Helper module for Project 3 Part B."""

from __future__ import annotations

import http.client
import http.server
import os
import socketserver
from typing import Callable, Optional

from network import config
from network.bank_server import BANK_HTTP_PORT

_ROLE = os.environ.get("CS130_ROLE", config.ROLE_MITM)

_ROLE_TABLE = {
    config.ROLE_DNS:    (config.DNS_IP,    config.DNS_MAC,    None),
    config.ROLE_BANK:   (config.BANK_IP,   config.BANK_MAC,   BANK_HTTP_PORT),
    config.ROLE_VICTIM: (config.VICTIM_IP, config.VICTIM_MAC, None),
    config.ROLE_MITM:   (config.MITM_IP,   config.MITM_MAC,   18005),
}

# Map virtual IP -> real localhost HTTP port
_HTTP_PORT_MAP = {
    config.BANK_IP: BANK_HTTP_PORT,
    config.MITM_IP: 18005,
}

# Logging (MUST call these to get credit)
def steal_credentials(username, password):
    print("MITM:   Intercepted Credentials")
    print("        Username: ", username)
    print("        Password: ", password, flush=True)


def steal_client_cookie(name, value):
    print("MITM:   Intercepted Cookie Sent By Client")
    print("        Name:  ", name)
    print("        Value: ", value, flush=True)


def steal_server_cookie(name, value):
    print("MITM:   Intercepted Cookie Set By Server")
    print("        Name:  ", name)
    print("        Value: ", value, flush=True)

def get_local_ip() -> str:
    return _ROLE_TABLE[_ROLE][0]


def get_local_mac() -> str:
    return _ROLE_TABLE[_ROLE][1]


def get_local_http_port() -> Optional[int]:
    return _ROLE_TABLE[_ROLE][2]


def get_bank_ip() -> str:
    return config.BANK_IP


def get_dns_ip() -> str:
    return config.DNS_IP


# Bus connection
_host = None
_host_lock = __import__("threading").Lock()


def _get_host():
    global _host
    if _host is None:
        with _host_lock:
            if _host is None:
                from network.host import Host
                _host = Host(ip=get_local_ip(), mac=get_local_mac(), role=_ROLE)
    return _host


def sendp(pkt) -> None:
    _get_host().send_frame(pkt)


def sniff(prn: Callable, stop: Optional[Callable] = None) -> None:
    _get_host().add_sniff_callback(prn)
    # The function does not block.

    if stop is not None:
        import time
        while not stop():
            time.sleep(0.05)


# HTTP shim
class HTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port=80, *, timeout=None, **kw):
        real_port = _HTTP_PORT_MAP.get(host, port)
        super().__init__("127.0.0.1", real_port,
                         timeout=timeout if timeout is not None
                         else http.client._GLOBAL_DEFAULT_TIMEOUT, **kw)


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def run_http_server(handler_cls):
    """Bind a BaseHTTPRequestHandler subclass to the virtual IP's real port."""
    port = get_local_http_port()
    if port is None:
        raise RuntimeError(f"Role {_ROLE!r} has no HTTP port configured")
    srv = _ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
    print(f"[{_ROLE}] listening at {get_local_ip()}", flush=True)
    srv.serve_forever()


# Launcher for the MITM
def run_mitm(arp_poisoner, dns_spoof, http_handler):
    """Wire all three attack stages and run forever.

    Spawns arp_poisoner in a background thread, registers dns_spoof as a
    per-frame sniff callback, and starts an HTTP server using http_handler.
    Students never have to think about threading, sniffing, or HTTP binding;
    they just provide the three pieces.
    """
    import threading
    threading.Thread(target=arp_poisoner, daemon=True).start()
    sniff(prn=dns_spoof)        # registers, returns immediately
    run_http_server(http_handler)

