# Bus / broker
BUS_HOST = "127.0.0.1"
BUS_PORT = 5557

# Network IPs
SUBNET = "10.38.8.0/24"
GATEWAY_IP = "10.38.8.1"
DNS_IP = "10.38.8.2"
BANK_IP = "10.38.8.3"
VICTIM_IP = "10.38.8.4"
MITM_IP = "10.38.8.5"

# MAC addresses (locally-administered, unicast)
DNS_MAC = "02:00:00:00:00:02"
BANK_MAC = "02:00:00:00:00:03"
VICTIM_MAC = "02:00:00:00:00:04"
MITM_MAC = "02:00:00:00:00:05"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

# Role names (sent on bus registration so the broker can address by name too)
ROLE_DNS = "dns"
ROLE_BANK = "bank"
ROLE_VICTIM = "victim"
ROLE_MITM = "mitm"

# Hostnames the victim will look up
BANK_HOSTNAME = "fakebank.com"
