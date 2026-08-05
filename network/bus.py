"""Virtual L2 bus"""

import argparse
import os
import socket
import struct
import threading
import time

from network import config

PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,  # magic
    2, 4,        # version
    0, 0,        # thiszone, sigfigs
    65535,       # snaplen
    1,           # linktype: LINKTYPE_ETHERNET
)


def _read_n(sock, n):
    """Read exactly n bytes from sock. Returns None on close."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _pack_msg(payload):
    return struct.pack("!I", len(payload)) + payload


def _recv_msg(sock):
    hdr = _read_n(sock, 4)
    if hdr is None:
        return None
    (length,) = struct.unpack("!I", hdr)
    return _read_n(sock, length)


def send_msg(sock, payload):
    sock.sendall(_pack_msg(payload))


class Broker:
    def __init__(self, host=config.BUS_HOST, port=config.BUS_PORT,
                 pcap_path=None, verbose=False):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.clients = {}      # sock -> (mac, role)
        self.by_mac = {}       # mac -> sock
        self.lock = threading.Lock()
        self.pcap_path = pcap_path
        self.pcap_fp = None
        if pcap_path:
            os.makedirs(os.path.dirname(pcap_path) or ".", exist_ok=True)
            self.pcap_fp = open(pcap_path, "wb")
            self.pcap_fp.write(PCAP_GLOBAL_HEADER)
            self.pcap_fp.flush()

    def _log_pcap(self, frame):
        if not self.pcap_fp:
            return
        ts = time.time()
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        rec = struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
        with self.lock:
            self.pcap_fp.write(rec)
            self.pcap_fp.flush()

    def serve(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(8)
        if self.verbose:
            print(f"[bus] listening on {self.host}:{self.port}")
        try:
            while True:
                csock, _ = srv.accept()
                t = threading.Thread(target=self._client_loop, args=(csock,),
                                     daemon=True)
                t.start()
        finally:
            srv.close()
            if self.pcap_fp:
                self.pcap_fp.close()

    def _client_loop(self, csock):
        # First message MUST be a registration: b"REG\0<mac>\0<role>"
        reg = _recv_msg(csock)
        if not reg or not reg.startswith(b"REG\0"):
            csock.close()
            return
        try:
            _, mac, role = reg.decode("ascii", errors="replace").split("\0", 2)
        except ValueError:
            csock.close()
            return
        mac = mac.lower()
        with self.lock:
            self.clients[csock] = (mac, role)
            self.by_mac[mac] = csock
        if self.verbose:
            print(f"[bus] register: {role} ({mac})")
        try:
            while True:
                frame = _recv_msg(csock)
                if frame is None:
                    break
                self._dispatch(csock, frame)
        finally:
            with self.lock:
                info = self.clients.pop(csock, None)
                if info and self.by_mac.get(info[0]) is csock:
                    del self.by_mac[info[0]]
            try:
                csock.close()
            except OSError:
                pass
            if self.verbose and info:
                print(f"[bus] disconnect: {info[1]}")

    def _dispatch(self, sender, frame):
        if len(frame) < 14:
            return
        # Ethernet: dst[0:6], src[6:12], type[12:14]
        dst_bytes = frame[0:6]
        dst_mac = ":".join("%02x" % b for b in dst_bytes)
        self._log_pcap(frame)

        with self.lock:
            if dst_mac == config.BROADCAST_MAC:
                targets = [s for s in self.clients if s is not sender]
            else:
                tgt = self.by_mac.get(dst_mac)
                targets = [tgt] if (tgt and tgt is not sender) else []

        for t in targets:
            try:
                t.sendall(_pack_msg(frame))
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=config.BUS_HOST)
    ap.add_argument("--port", type=int, default=config.BUS_PORT)
    ap.add_argument("--pcap", default="output/packetdump.pcap")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    Broker(args.host, args.port, pcap_path=args.pcap,
           verbose=args.verbose).serve()


if __name__ == "__main__":
    main()
