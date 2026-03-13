from scapy.all import sniff, ARP, DHCP, BOOTP, Ether, get_if_list, conf
from datetime import datetime
import sqlite3

DB_PATH = "data.sqlite"

GREEN  = "\033[92m"
RED    = "\033[91m"
PURPLE = "\033[95m"
BLUE   = "\033[94m"
RESET  = "\033[0m"

def load_whitelist(db_path):
    conn = sqlite3.connect(db_path)
    cur  = conn.cursor()
    cur.execute('SELECT Location, Tag, MAC FROM "CIS 202 MAC"')
    rows = cur.fetchall()
    conn.close()
    return {mac.lower().strip(): {"tag": tag, "location": location} for location, tag, mac in rows}

seen      = set()
WHITELIST = {}

def handle_device(mac, ip, protocol, now):
    if mac in seen:
        return
    seen.add(mac)

    proto_tag = f"{PURPLE}[ARP]{RESET}"  if protocol == "ARP"  else f"{BLUE}[DHCP]{RESET}"

    if mac in WHITELIST:
        entry = WHITELIST[mac]
        print(f"{GREEN}[ALLOWED]{RESET}  {proto_tag}  {now}  {mac}  {ip}  tag={entry['tag']}  location={entry['location']}")
    else:
        print(f"{RED}[ROGUE DEVICE DETECTED]{RESET}  {proto_tag}\n"
              f"           {now}  {mac}  {ip}")

def handle_packet(packet):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if packet.haslayer(ARP) and packet[ARP].op in (1, 2):
        mac = packet[ARP].hwsrc.lower()
        ip  = packet[ARP].psrc
        if ip != "0.0.0.0":
            handle_device(mac, ip, "ARP", now)

    elif packet.haslayer(DHCP):
        mac     = packet[Ether].src.lower()
        options = {o[0]: o[1] for o in packet[DHCP].options if isinstance(o, tuple)}
        if options.get("message-type") not in (1, 3):
            return
        req_ip  = str(options.get("requested_addr", "")) or None
        offered = str(packet[BOOTP].yiaddr)
        ip      = req_ip or (offered if offered != "0.0.0.0" else "unknown")
        handle_device(mac, ip, "DHCP", now)

def start_monitor():
    global WHITELIST
    WHITELIST = load_whitelist(DB_PATH)
    print(f"[*] Whitelist loaded: {len(WHITELIST)} entries")
    print(f"[*] Starting on: {conf.iface}")
    print("-" * 60)
    sniff(
        iface=str(conf.iface),
        filter="arp or (udp and (port 67 or port 68))",
        prn=handle_packet,
        store=0
    )

if __name__ == "__main__":
    start_monitor()