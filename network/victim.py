"""Victim client"""

import os
import threading
import time
from urllib.parse import urlencode

# Force the role BEFORE importing cs130
os.environ["CS130_ROLE"] = "victim"

from scapy.all import DNS, DNSQR, IP, UDP

import cs130
from network import config
from network.host import Host  # noqa: F401 — Host is constructed via cs130


COLOR = "\033[35m"
RESET = "\033[0m"


def banner(text):
    print(f"{COLOR}==========    {text}    =========={RESET}", flush=True)


class DNSResolver:
    """DNS client that sends one query and waits for the first reply."""

    def __init__(self):
        self.host = cs130._get_host()  # share the bus connection
        self._answer = None
        self._event = threading.Event()
        self.host.add_sniff_callback(self._on_pkt)

    def _on_pkt(self, pkt):
        if DNS not in pkt:
            return
        dns = pkt[DNS]
        if dns.qr != 1 or dns.ancount < 1:
            return
        try:
            ip = dns.an.rdata
        except Exception:
            return
        # First reply wins 
        if self._answer is None:
            self._answer = ip
            self._event.set()

    def resolve(self, name, timeout=3.0):
        self._answer = None
        self._event.clear()
        query = (
            IP(src=config.VICTIM_IP, dst=config.DNS_IP)
            / UDP(sport=33333, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=name))
        )
        self.host.send_ip(query)
        if self._event.wait(timeout):
            return self._answer
        return None


class VictimSession:
    def __init__(self):
        self.cookies = {}
        self.resolver = DNSResolver()
        self.bank_ip = None

    def _resolve(self):
        ip = self.resolver.resolve(config.BANK_HOSTNAME)
        if ip is None:
            print(f"[DNS ERROR] Failed to resolve '{config.BANK_HOSTNAME}'",
                  flush=True)
            return False
        self.bank_ip = ip
        print(f"[DNS] {config.BANK_HOSTNAME} resolved to: {ip}", flush=True)
        if ip == config.MITM_IP:
            print("[+] DNS Spoofing SUCCESS — resolved to MITM", flush=True)
        return True

    def _request(self, method, path, body=None):
        conn = cs130.HTTPConnection(self.bank_ip, 80, timeout=5)
        headers = {"Host": f"{config.BANK_HOSTNAME}"}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Content-Length"] = str(len(body))
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            text = resp.read().decode("utf-8", errors="replace")
            sc = resp.getheader("Set-Cookie")
            if sc:
                # Parse only "name=value" before first ";"
                first = sc.split(";", 1)[0]
                if "=" in first:
                    name, val = first.split("=", 1)
                    self.cookies[name.strip()] = val.strip()
            return resp.status, text
        except Exception as e:
            return None, f"[error] {e}"
        finally:
            conn.close()

    def login(self):
        banner("STAGE 1/4: Logging in...")
        body = urlencode({"username": "Sabrina", "password": "PleaseComeBack"})
        status, text = self._request("POST", "/login", body)
        print(f"Login Response: {text}", flush=True)

    def homepage(self):
        banner("STAGE 2/4: Visiting homepage...")
        status, text = self._request("GET", "/")
        print(f"Homepage Response: {text}", flush=True)

    def transfer(self):
        banner("STAGE 3/4: Transferring funds...")
        body = urlencode({"from": "sabrina", "to": "jensen", "amount": "1000"})
        status, text = self._request("POST", "/transfer", body)
        print(f"Transfer Response: {text}", flush=True)

    def logout(self):
        banner("STAGE 4/4: Logging out...")
        status, text = self._request("POST", "/logout")
        print(f"Logout Response: {text}", flush=True)


def main():
    sess = VictimSession()
    # Give the MITM a generous head start so its ARP poisoning lands before we send the first DNS query. 
    time.sleep(3)
    if not sess._resolve():
        return
    sess.login()
    time.sleep(0.5)
    sess.homepage()
    time.sleep(0.5)
    sess.transfer()
    time.sleep(0.5)
    sess.logout()

if __name__ == "__main__":
    main()
