"""Simulated DNS server.

The send is commented out below so that the MITM always wins the DNS race. Uncomment to verify benign behaviour.
"""

import threading
import time

from scapy.all import DNS, DNSRR, IP, UDP

from network import config
from network.host import Host


RECORDS = {
    config.BANK_HOSTNAME + ".": config.BANK_IP,
}

def main():
    host = Host(ip=config.DNS_IP, mac=config.DNS_MAC, role=config.ROLE_DNS,
                verbose=False)
    print(f"[dns] listening at {config.DNS_IP}", flush=True)

    def reply_thread():
        while True:
            pkt = host.recv_packet(timeout=1.0)
            if pkt is None:
                continue
            if not (UDP in pkt and pkt[UDP].dport == 53 and DNS in pkt):
                continue
            dns = pkt[DNS]
            if dns.qr != 0 or dns.qdcount < 1:
                continue
            qname = dns[0].qd.qname.decode("ascii", errors="replace")
            print(f"[dns] received query for {qname!r} from {pkt[IP].src}",
                  flush=True)
            if qname not in RECORDS:
                continue
            answer_ip = RECORDS[qname]
            response = (
                IP(src=config.DNS_IP, dst=pkt[IP].src)
                / UDP(sport=53, dport=pkt[UDP].sport)
                / DNS(id=dns.id, qr=1, aa=1, qd=dns.qd,
                      an=DNSRR(rrname=qname, ttl=60, rdata=answer_ip))
            )
            # the following line is intentionally commented out so that the student's MITM always wins the DNS race.
            # Uncomment to verify benign behaviour, then comment again before testing your MITM.

            # host.send_ip(response)

    t = threading.Thread(target=reply_thread, daemon=True)
    t.start()
    while True:
        time.sleep(60)

if __name__ == "__main__":
    main()
