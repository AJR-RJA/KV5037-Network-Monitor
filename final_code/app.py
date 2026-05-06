import sqlite3
from scapy.all import sniff, ARP, DHCP, Ether, BOOTP
from prometheus_client import start_http_server, Counter, Gauge

# Path to the SQLite database containing the MAC whitelist
DB_PATH = "data.sqlite"

# ── Prometheus metrics ─────────────────────────────────────────────────────
# Counts every device event, labelled by protocol (ARP/DHCP) and whether it's whitelisted
devices_total = Counter(
    "network_device_events_total",
    "Total device connection events",
    ["protocol", "whitelisted"]
)

# Tracks unique rogue devices seen this session
rogue_gauge = Gauge(
    "network_rogue_devices_seen",
    "Unique rogue devices seen this session"
)

# Tracks unique allowed devices seen this session
allowed_gauge = Gauge(
    "network_allowed_devices_seen",
    "Unique allowed devices seen this session"
)

# ── Whitelist loader ───────────────────────────────────────────────────────
def load_whitelist():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Fetch only the MAC column from the whitelist table
    c.execute('SELECT MAC FROM "CIS 202 MAC"')

    # Uppercase string of MAC for searching database
    macs = {row[0].upper() for row in c.fetchall()}

    conn.close()
    return macs

# Loaded whitelist
WHITELIST = load_whitelist()
print(f"Loaded {len(WHITELIST)} MACs")
print(f"Prometheus metrics → http://localhost:8000/metrics")
print("Listening for ARP and DHCP traffic\n")

# Tracks MACs already seen this session to avoid duplicate metric increments
seen = set()

# ── Packet handler ─────────────────────────────────────────────────────────
def handle_packet(packet):

    mac = None  # Will be set if the packet is ARP or DHCP

    # ARP section — request (op 1) and reply (op 2)
    if packet.haslayer(ARP) and packet[ARP].op in (1, 2):
        mac = packet[ARP].hwsrc.upper()  # Sender MAC address
        ip  = packet[ARP].psrc           # Sender IP address
        src = "ARP"

    # DHCP section — client MAC is in the Ethernet header
    elif packet.haslayer(DHCP):
        mac = packet[Ether].src.upper()  # Client MAC from Ethernet frame
        ip  = str(packet[BOOTP].ciaddr)  # Client IP (may be 0.0.0.0 if not yet assigned)
        src = "DHCP"

    # Only process if we extracted a MAC
    if mac:
        if mac in WHITELIST:
            print(f"[ALLOWED]  {src}  MAC: {mac}  IP: {ip}")

            # Only increment metrics once per unique MAC per session
            if mac not in seen:
                devices_total.labels(protocol=src, whitelisted="true").inc()
                allowed_gauge.inc()

        else:
            print(f"[ROGUE]    {src}  MAC: {mac}  IP: {ip}")

            # Only increment metrics once per unique MAC per session
            if mac not in seen:
                devices_total.labels(protocol=src, whitelisted="false").inc()
                rogue_gauge.inc()

        seen.add(mac)

# ── Entry point ────────────────────────────────────────────────────────────
# Start Prometheus metrics server on port 8000 before sniffing begins
start_http_server(8000)

# Start passive sniffing using a BPF filter to capture only ARP and DHCP traffic
# filter: "arp" catches ARP packets; "udp port 67 or 68" catches DHCP
# store=0: don't store packets in memory
sniff(
    filter="arp or (udp and (port 67 or port 68))",
    prn=handle_packet,
    store=0
)
