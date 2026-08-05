import sys
from scapy.all import rdpcap, IP, TCP, ARP

def main():

    if len(sys.argv) != 2:
        print("Usage: python3 detector.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]

    detected_syn_scanners = []
    detected_arp_spoofers = []

    # SYN scan tracking
    syn_sent = {}
    synack_received = {}

    # ARP spoofing tracking
    outstanding_requests = {}
    unsolicited_counts = {}

    try:
        packets = rdpcap(pcap_file)

    except Exception as e:
        print(f"Failed to process file: {e}")
        sys.exit(1)

    for pkt in packets:

        try:
            # --------------------------------
            # TCP / SYN Scanner Detection
            # --------------------------------
            if pkt.haslayer(IP) and pkt.haslayer(TCP):

                ip = pkt[IP]
                tcp = pkt[TCP]

                src_ip = ip.src
                dst_ip = ip.dst

                flags = tcp.flags

                # SYN packet
                if (tcp.flags & 0x02) and not (tcp.flags & 0x10):
                    syn_sent[src_ip] = syn_sent.get(src_ip, 0) + 1

                # SYN-ACK packet
                elif (tcp.flags & 0x02) and (tcp.flags & 0x10):
                    synack_received[dst_ip] = (
                        synack_received.get(dst_ip, 0) + 1
                    )

            # --------------------------------
            # ARP Spoofing Detection
            # --------------------------------
            elif pkt.haslayer(ARP):

                arp = pkt[ARP]

                sender_mac = arp.hwsrc
                sender_ip = arp.psrc
                target_ip = arp.pdst

                # ARP Reply
                if arp.op == 2:

                    match_key = (target_ip, sender_ip)

                    if (match_key in outstanding_requests and
                        len(outstanding_requests[match_key]) > 0):

                        outstanding_requests[match_key].pop(0)

                    else:
                        unsolicited_counts[sender_mac] = (
                            unsolicited_counts.get(sender_mac, 0) + 1
                        )

                # ARP Request
                elif arp.op == 1:

                    key = (sender_ip, target_ip)

                    if key not in outstanding_requests:
                        outstanding_requests[key] = []

                    outstanding_requests[key].append(1)

        except Exception:
            continue

    # --------------------------------
    # Detect SYN Scanners
    # --------------------------------
    for ip, syn_count in syn_sent.items():

        if syn_count > 5:

            synack_count = synack_received.get(ip, 0)

            if synack_count == 0 or (syn_count / synack_count) >= 3.0:
                detected_syn_scanners.append(ip)

    # --------------------------------
    # Detect ARP Spoofers
    # --------------------------------
    for mac, count in unsolicited_counts.items():

        if count > 5:
            detected_arp_spoofers.append(mac)

    # --------------------------------
    # Output
    # --------------------------------
    print("Unauthorized SYN scanners:")

    for ip in sorted(detected_syn_scanners):
        print(ip)

    print("Unauthorized ARP spoofers:")

    for mac in sorted(detected_arp_spoofers):
        print(mac)

if __name__ == "__main__":
    main()