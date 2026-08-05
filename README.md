# Linux Network Security Analysis & MITM Attack Simulation

A Python-based network security project focused on packet analysis, network attack simulation, and intrusion detection. The project combines traffic forensics using Wireshark with offensive security techniques such as ARP poisoning and DNS spoofing, followed by the implementation of automated detection tools for identifying malicious network behavior.

---

## Project Overview

This project consists of three major components:

- **Network Traffic Analysis** using Wireshark
- **Monster-in-the-Middle (MITM) Attack Simulation**
- **Automated Intrusion Detection using Python**

The objective was to understand how insecure network protocols can be exploited and how malicious activity can be detected from packet captures.

---

## Features

### Packet Analysis (Wireshark)

- Analyzed packet captures (`.pcap`) to identify:
  - HTTP web servers
  - Directory traversal attacks
  - FTP password brute-force attempts
  - Plaintext credentials
  - Legacy TLS versions
  - DNS source-port reuse
  - TCP Initial Sequence Number (ISN) behavior
  - Reflected Cross-Site Scripting (XSS) attacks

- Utilized advanced Wireshark filters and TCP stream analysis to investigate network behavior.

---

### Monster-in-the-Middle Attack

Implemented a complete MITM attack inside a simulated LAN environment.

#### ARP Poisoning
- Forged unsolicited ARP replies
- Redirected victim traffic through the attacker's machine
- Maintained poisoned ARP cache throughout the session

#### DNS Spoofing
- Intercepted DNS requests
- Crafted forged DNS responses using Scapy
- Redirected victim HTTP traffic to the attacker before legitimate DNS replies arrived

#### HTTP Proxy & Traffic Manipulation
- Built a transparent HTTP proxy
- Captured usernames and passwords from login requests
- Extracted client and server session cookies
- Modified outgoing money-transfer requests
- Rewrote server responses to conceal the attack from the victim

---

### Network Intrusion Detection

Developed an automated packet inspection tool capable of detecting:

- SYN scanning attacks
- ARP spoofing attacks

The detector parses PCAP files and identifies malicious hosts based on TCP flag analysis and unsolicited ARP replies.

---

## Technologies Used

- Python 3
- Scapy
- dpkt
- Wireshark
- HTTP Protocol
- TCP/IP
- Ethernet
- ARP
- DNS

---

## Skills Demonstrated

- Network Security
- Packet Analysis
- Traffic Forensics
- Protocol Analysis
- ARP Poisoning
- DNS Spoofing
- Man-in-the-Middle Attacks
- HTTP Request Manipulation
- Session Hijacking Concepts
- Intrusion Detection
- Python Networking
- PCAP Analysis

---

## Repository Structure

```
.
├── answers.txt             # Wireshark analysis answers
├── mitm.py                 # MITM attack implementation
├── detector.py             # Intrusion detection tool
├── run.py                  # Network simulator
├── sample.pcap
├── trace.pcap
├── output/
│   └── packetdump.pcap
├── network/
│   ├── bank_server.py
│   ├── dns_server.py
│   ├── victim.py
│   ├── host.py
│   └── ...
└── cs130.py
```

---

## Learning Outcomes

Through this project I gained experience with:

- Inspecting network traffic using Wireshark
- Understanding Ethernet, ARP, DNS, TCP, and HTTP protocols
- Crafting raw packets using Scapy
- Performing ARP cache poisoning
- Conducting DNS spoofing attacks
- Building transparent HTTP proxies
- Detecting reconnaissance activity from packet captures
- Developing automated network security analysis tools

---

## Disclaimer

This repository was developed for an academic network security course in a controlled laboratory environment. All attack simulations were performed on an isolated virtual network provided as part of the assignment and are intended solely for educational purposes.
