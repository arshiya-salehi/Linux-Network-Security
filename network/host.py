"""Host base class for the simulated LAN."""

from __future__ import annotations

import queue
import socket
import struct
import threading
import time
from typing import Callable, Optional

from scapy.all import Ether, ARP, IP, UDP, TCP, Raw  # noqa: F401
from scapy.layers.inet import IP as _IP

from network import config
from network.bus import send_msg, _recv_msg


class Host:
    def __init__(self, ip: str, mac: str, role: str,
                 bus_host: str = config.BUS_HOST,
                 bus_port: int = config.BUS_PORT,
                 verbose: bool = False):
        self.ip = ip
        self.mac = mac.lower()
        self.role = role
        self.verbose = verbose

        # Connect to bus
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._connect_retry(bus_host, bus_port)
        reg = f"REG\0{self.mac}\0{self.role}".encode("ascii")
        send_msg(self.sock, reg)

        # ARP cache: ip -> mac
        self.arp_cache: dict[str, str] = {}
        self._arp_waiters: dict[str, threading.Event] = {}

        self._inbox: queue.Queue = queue.Queue()
        self._sniff_callbacks: list[Callable] = []

        self._stop = threading.Event()
        self._rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._rx_thread.start()

    # low-level bus IO
    def _connect_retry(self, host, port, attempts=40, delay=0.1):
        for _ in range(attempts):
            try:
                self.sock.connect((host, port))
                return
            except OSError:
                time.sleep(delay)
        raise RuntimeError(f"Could not connect to bus at {host}:{port}")

    def send_frame(self, pkt):
        data = bytes(pkt)
        try:
            send_msg(self.sock, data)
        except OSError:
            pass

    def _rx_loop(self):
        while not self._stop.is_set():
            data = _recv_msg(self.sock)
            if data is None:
                break
            try:
                pkt = Ether(data)
            except Exception:
                continue

            for cb in list(self._sniff_callbacks):
                try:
                    cb(pkt)
                except Exception as e:
                    if self.verbose:
                        print(f"[{self.role}] sniff cb error: {e}")

            if ARP in pkt:
                self._on_arp(pkt[ARP])
                continue

            dst = pkt.dst.lower()
            if dst != self.mac and dst != config.BROADCAST_MAC:
                continue

            if IP in pkt and pkt[IP].dst != self.ip and pkt[IP].dst != "255.255.255.255":
                continue
            self._inbox.put(pkt)

    def _on_arp(self, arp):
        if arp.op == 1:
            if arp.pdst == self.ip:
                # Respond with our MAC
                reply = (
                    Ether(src=self.mac, dst=arp.hwsrc)
                    / ARP(op=2, hwsrc=self.mac, psrc=self.ip,
                          hwdst=arp.hwsrc, pdst=arp.psrc)
                )
                self.send_frame(reply)
        elif arp.op == 2:  # reply
            self.arp_cache[arp.psrc] = arp.hwsrc.lower()
            ev = self._arp_waiters.pop(arp.psrc, None)
            if ev is not None:
                ev.set()

    def resolve_mac(self, ip: str, timeout: float = 2.0) -> Optional[str]:
        if ip in self.arp_cache:
            return self.arp_cache[ip]
        ev = self._arp_waiters.setdefault(ip, threading.Event())
        req = (
            Ether(src=self.mac, dst=config.BROADCAST_MAC)
            / ARP(op=1, hwsrc=self.mac, psrc=self.ip,
                  hwdst="00:00:00:00:00:00", pdst=ip)
        )
        self.send_frame(req)
        if ev.wait(timeout):
            return self.arp_cache.get(ip)
        return None

    def send_ip(self, ip_pkt):
        dst_ip = ip_pkt.dst
        dst_mac = self.resolve_mac(dst_ip)
        if dst_mac is None:
            if self.verbose:
                print(f"[{self.role}] ARP resolution failed for {dst_ip}")
            return False
        frame = Ether(src=self.mac, dst=dst_mac) / ip_pkt
        self.send_frame(frame)
        return True

    # Sniffing
    def add_sniff_callback(self, cb: Callable):
        self._sniff_callbacks.append(cb)

    def recv_packet(self, timeout: Optional[float] = None):
        try:
            return self._inbox.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
