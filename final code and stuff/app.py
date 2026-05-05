import sqlite3
from scapy.all import sniff, ARP, DHCP, Ether, BOOTP
 
# Path to the SQLite database containing the MAC whitelist
DB_PATH = "data.sqlite"
 
def load_whitelist():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
 
    # Fetch only the MAC column from the whitelist table
    c.execute('SELECT MAC FROM "CIS 202 MAC"')
 
    # uppercase sting of mac for searching database
    macs = {row[0].upper() for row in c.fetchall()}
 
    conn.close()
    return macs
 
# loaded whitelist
WHITELIST = load_whitelist()
print(f"Loaded {len(WHITELIST)} MACs")
print("ARP and DHCP traffic\n")
 
def handle_packet(packet):
    
    mac = None  # none for now, Will be set if the packet is ARP or DHCP
 
    # ARP section
    # arp request and reply, who has this ID and i have this ID

    if packet.haslayer(ARP) and packet[ARP].op in (1, 2):
        mac = packet[ARP].hwsrc.upper()  # Sender MAC address
        ip  = packet[ARP].psrc           # Sender IP address
        src = "ARP"
 
    # DHCP section
    # DHCP packets carry the client MAC in the Ethernet header
    elif packet.haslayer(DHCP):
        mac = packet[Ether].src.upper()  # Client MAC from Ethernet frame
        ip  = str(packet[BOOTP].ciaddr)  # Client IP may be 0.0.0.0 if not yet assigned
        src = "DHCP"
 
    # Only if we get a MAC
    if mac:
        if mac in WHITELIST:
            # MAC is in the database device is authorised
            print(f"[ALLOWED]  {src}  MAC: {mac}  IP: {ip}")
        else:
            # MAC is not in the database rogue device
            print(f"[ROGUE]    {src}  MAC: {mac}  IP: {ip}")
 
# Start passive sniffing using a BPF filter to capture only ARP and DHCP traffic
# filter: "arp" catches ARP packets; "udp port 67 or 68" catches DHCP
# store=0: don't store packets in memory
sniff(
    filter="arp or (udp and (port 67 or port 68))",
    prn=handle_packet,
    store=0
)