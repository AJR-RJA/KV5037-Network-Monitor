from scapy.all import sniff, ARP, DHCP, BOOTP, Ether, get_if_list, conf  
from datetime import datetime  
from prometheus_client import start_http_server, Counter, Gauge  
import sqlite3, requests, json, time  
import certifi  
import urllib3  
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

# ── Grafana Cloud credentials ──────────────────────────────────────────────  
LOKI_URL     = "https://logs-prod-035.grafana.net/loki/api/v1/push"  
LOKI_USER    = "1515661"  
LOKI_API_KEY = "glc_eyJvIjoiMTY5ODI2MSIsIm4iOiJjb2RlLWNvZGUxIiwiayI6IjgxeDljZk4wcThGTjNoODJ4Mmo0TW5LciIsIm0iOnsiciI6InVzIn19"   # ← paste your token here  

DB_PATH = "data.sqlite"  

GREEN  = "\033[92m"  
RED    = "\033[91m"  
PURPLE = "\033[95m"  
BLUE   = "\033[94m"  
RESET  = "\033[0m"  

# ── Prometheus metrics ─────────────────────────────────────────────────────  
devices_total  = Counter("network_device_events_total",  
                         "Total device connection events",  
                         ["protocol", "whitelisted"])  
rogue_gauge    = Gauge("network_rogue_devices_seen",  
                       "Unique rogue devices seen this session")  
allowed_gauge  = Gauge("network_allowed_devices_seen",  
                       "Unique allowed devices seen this session")  

# ── Loki push ──────────────────────────────────────────────────────────────  
def push_loki(mac, ip, protocol, whitelisted, tag="", location=""):  
    log_line = json.dumps({  
        "mac": mac, "ip": ip, "protocol": protocol,  
        "whitelisted": whitelisted, "tag": tag, "location": location  
    })  
    payload = {"streams": [{  
        "stream": {  
            "job":         "network_monitor",  
            "whitelisted": str(whitelisted).lower(),  
            "protocol":    protocol  
        },  
        "values": [[str(int(time.time() * 1e9)), log_line]]  
    }]}  
    try:  
        requests.post(LOKI_URL, json=payload,  
                      auth=(LOKI_USER, LOKI_API_KEY),  
                      verify=False,    # ← bypass SSL check  
                      timeout=3)  
    except Exception as e:  
        print(f"[WARN] Loki push failed: {e}")   

# ── Whitelist loader ───────────────────────────────────────────────────────  
def load_whitelist(db_path):  
    conn = sqlite3.connect(db_path)  
    cur  = conn.cursor()  
    cur.execute('SELECT Location, Tag, MAC FROM "CIS 202 MAC"')  
    rows = cur.fetchall()  
    conn.close()  
    return {mac.lower().strip(): {"tag": tag, "location": location}  
            for location, tag, mac in rows}  

seen      = set()  
WHITELIST = {}  

# ── Device handler ─────────────────────────────────────────────────────────  
def handle_device(mac, ip, protocol, now):  
    if mac in seen:  
        return  
    seen.add(mac)  

    proto_tag = f"{PURPLE}[ARP]{RESET}" if protocol == "ARP" else f"{BLUE}[DHCP]{RESET}"  

    if mac in WHITELIST:  
        entry = WHITELIST[mac]  
        print(f"{GREEN}[ALLOWED]{RESET}  {proto_tag}  {now}  {mac}  {ip}"  
              f"  tag={entry['tag']}  location={entry['location']}")  
        devices_total.labels(protocol=protocol, whitelisted="true").inc()  
        allowed_gauge.inc()  
        push_loki(mac, ip, protocol, True, entry["tag"], entry["location"])  
    else:  
        print(f"{RED}[ROGUE DEVICE DETECTED]{RESET}  {proto_tag}\n"  
              f"           {now}  {mac}  {ip}")  
        devices_total.labels(protocol=protocol, whitelisted="false").inc()  
        rogue_gauge.inc()  
        push_loki(mac, ip, protocol, False)  

# ── Packet handler ─────────────────────────────────────────────────────────  
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

# ── Entry point ────────────────────────────────────────────────────────────  
def start_monitor():  
    global WHITELIST  
    WHITELIST = load_whitelist(DB_PATH)  
    start_http_server(8000)  
    print(f"[*] Whitelist loaded: {len(WHITELIST)} entries")  
    print(f"[*] Prometheus metrics → http://localhost:8000/metrics")  
    print(f"[*] Loki push → {LOKI_URL}")  
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