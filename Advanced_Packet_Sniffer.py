from scapy.all import conf, Ether, ARP, IP, TCP, UDP, ICMP, DNS, DNSQR, sniff, wrpcap
from collections import defaultdict, deque
import scapy.arch.windows # ייבוא ישיר לווינדוס ליתר ביטחון
conf.use_pcap = True
import platform
import subprocess
import json
import time
import argparse
import sys

def get_inter_bytes(): #חישוב בייטים נשלחים ונכנסים מהכרטיס רשת בכל מערכת הפעלה בשביל לחשב דלטה בפונקציה למטה
    
    system = platform.system()
    stats = {}

    if system == "Linux":
        # נקרא מהקרנל של לינוקס
        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()[2:] # מדלג על הכותרות
            for line in lines:
                parts = line.split()
                iface = parts[0].strip(":")
                stats[iface] = {"rx": int(parts[1]), "tx": int(parts[9])}

    elif system == "Windows":
        # 1. יצירת מילון שמקשר בין השם הידידותי ל-GUID ש-Scapy צריכה
        # { 'Ethernet': '\\Device\\NPF_{...}', 'Wi-Fi': '\\Device\\NPF_{...}' }
        name_to_pcap = {}
        for iface in conf.ifaces.values():
            name_to_pcap[iface.description] = getattr(iface, 'pcap_name', iface.name)
            name_to_pcap[iface.name] = getattr(iface, 'pcap_name', iface.name)

        ps_command = (
            "Get-NetAdapter | "
            "Select-Object Name, InterfaceDescription, ReceivedBytes, SentBytes | "
            "ConvertTo-Json"
        )

        try:
            process = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True, text=True, encoding="utf-8", errors="ignore"
            )
            if  process.stdout and process.stdout.strip():
                data = json.loads(process.stdout)
                if isinstance(data, dict): data = [data]


            for item in data:
                
                # מנסים למצוא התאמה לפי השם או לפי התיאור של האדפטר
                scapy_name = name_to_pcap.get(item['Name']) or name_to_pcap.get(item['InterfaceDescription'])
                
                if scapy_name:
                    stats[scapy_name] = {
                        "rx": int(item['ReceivedBytes']),
                        "tx": int(item['SentBytes'])
                    }

        except Exception as e:
            print(f"PowerShell error: {e}")

    # החזרת stats בסוף הפונקציה (מחוץ ל-if/else) כדי שתמיד יחזור מילון
    return stats


def resolve_Iface_NAME_to_ScapySniffing_NAME(iface_input):
    # מקבל pcap name כמו DEVICE\\NPF_{GUID} ומחזיר תיאור של סקאפי כמו Intel(R) 82579V Gigabit Network Connection

    try:

        for iface in conf.ifaces.values():
            name = iface.name
            desc = getattr(iface, "description", None)
            pcap = getattr(iface, "pcap_name", name)

            if iface_input in (name, desc, pcap):

                # הכי יציב ל- sniff בסקאפי זה השם שחוזר מהדיסקריפשן
                return desc if desc else name
            
    except Exception as e:
        print(f"! Interface normalization error: {e}")

    return iface_input




def pick_active_interfaces():#פונקציה שמחזירה את כרטיס הרשת הפעיל בממשק שהקוד רץ עליו על ידי בדיקת יציאה לאינטרנט או על ידי חישוב דלטה של הביטים הנכנסים והיוצאים על כרטיס הרשת

    try:
        # Scapy יודע מה ה-interface שיוצא ל-Default Gateway
        route = conf.route.route("8.8.8.8")
        iface_name = route[0]
        src_ip = route[1]

        for iface in conf.ifaces.values():
            if iface.ip == src_ip:
                return resolve_Iface_NAME_to_ScapySniffing_NAME(iface)

    except Exception:
        print("Could not determine via routing table, measuring traffic...")


    

    try:
        # פקודה שמרעננת את רשימת הממשקים במידה והיא ריקה או תקועה
        conf.ifaces.reload() 
        interfaces_list = []
        # אנחנו רצים על המילון בצורה בטוחה
        for iface_key in conf.ifaces.data:
            iface = conf.ifaces.data[iface_key]
            
            # שליפת השם ש-Scapy צריכה ל-Sniffing
            # בווינדוס זה ה-pcap_name (למשל Device\NPF...)
            scapy_name = getattr(iface, 'pcap_name', iface.name)
            
            # בדיקה אם הממשק פעיל (יש לו IP והוא לא Loopback)
            if iface.ip and iface.ip != "0.0.0.0" and iface.ip != "127.0.0.1":
                interfaces_list.append(scapy_name)
                

        if not interfaces_list:
            return None
        
        BytesDict_start = get_inter_bytes()
        time.sleep(1)
        BytesDict_end = get_inter_bytes()

        max_delta = -1
        best_iface = interfaces_list[0]

        for iface in interfaces_list:
            if iface in BytesDict_start and iface in BytesDict_end:
                delta = (BytesDict_end[iface]['rx'] + BytesDict_end[iface]['tx']) - \
                        (BytesDict_start[iface]['rx'] + BytesDict_start[iface]['tx'])
                
                if delta > max_delta:
                    max_delta = delta
                    best_iface = iface
        return resolve_Iface_NAME_to_ScapySniffing_NAME(best_iface)
        

    except Exception as e:
        print(f"Error accessing interfaces: {e}")
        # פתרון חירום למקרה שה-conf.ifaces עדיין קורס:
        print("Attempting fallback method...")
        from scapy.arch import get_if_list
        interfaces_list = get_if_list()
        return resolve_Iface_NAME_to_ScapySniffing_NAME(interfaces_list[0]) if interfaces_list else None #להחזיר את הממשק הראשון כברירת מחדל אם לא עבדו 2 השיטות הקודמות 
    

def init_state():
    return {
        "total_packets": 0,
        "total_bytes": 0,

        "bytes_sent_per_ip": defaultdict(int),
        "bytes_received_per_ip": defaultdict(int),
        "packets_sent_per_ip": defaultdict(int),
        "packets_received_per_ip": defaultdict(int),

        "scan_activity_per_src": defaultdict(deque),   # src_ip -> deque[(ts, dst_ip, dport)]
        "icmp_times_per_src": defaultdict(deque),      # src_ip -> deque[ts]
        "dns_queries_per_src": defaultdict(deque),     # src_ip -> deque[(ts, qname)]
        "global_throughput_window": deque(),           # deque[(ts, size)]
        "throughput_per_src": defaultdict(deque),      # src_ip -> deque[(ts, size)]

        "packet_count_based_on_protocol": defaultdict(int),
        "packet_log": [],
        "output_to_a_file": [],
        "observations": []
    }


def handle_pkt(packet, state):
    packet_count_based_on_protocol = state["packet_count_based_on_protocol"]
    packet_log = state["packet_log"]
    output_to_a_file = state["output_to_a_file"]


    state["total_packets"] += 1
    packet_size = len(packet)
    state["total_bytes"] += packet_size

    if Ether in packet: # layer 2
        packet_count_based_on_protocol['Ether'] += 1

        src_MAC = packet[Ether].src
        dst_MAC = packet[Ether].dst
        type = packet[Ether].type

    if ARP in packet: #layer 3
        packet_count_based_on_protocol['ARP'] += 1

        arp_type = packet[ARP].hwtype
        arp_proto_type = packet[ARP].ptype
        arp_opcode = packet[ARP].op
        MAC_src = packet[ARP].hwsrc
        IP_src = packet[ARP].psrc
        MAC_dst = packet[ARP].hwdst
        IP_dst = packet[ARP].pdst

        output = f"[ARP] {MAC_src}:{MAC_dst}:{arp_type}:{arp_proto_type}:{arp_opcode} -> {IP_src}:{IP_dst}"


    elif IP in packet:
        packet_count_based_on_protocol['IP'] += 1

        src = packet[IP].src
        dst = packet[IP].dst
        protocol = packet[IP].proto

        state["bytes_sent_per_ip"][src] += packet_size #מעדכן את הדיפולט דיקט ב- State לכתובת ip שהפקטה ממנה למעשה מוסיף את האורך
        state["bytes_received_per_ip"][dst] += packet_size # עושה אותו דבר עבר לכתובת היעד בכמה נשלחו אליה
        state["packets_sent_per_ip"][src] += 1
        state["packets_received_per_ip"][dst] += 1

        if protocol == 6 and TCP in packet: #TCP #layer 4
            packet_count_based_on_protocol['TCP'] += 1
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            output = f"[TCP] {src}:{sport} -> {dst}:{dport}"

        elif protocol == 17 and UDP in packet: #UDP
            packet_count_based_on_protocol['UDP'] += 1
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            output = f"[UDP] {src}:{sport} -> {dst}:{dport}"

        elif protocol == 1 and ICMP in packet: #ICMP
            packet_count_based_on_protocol['ICMP'] +=1
            icmp_type = packet[ICMP].type
            output = f"[ICMP] {src}:{icmp_type} -> {dst}"
    
        else:
            packet_count_based_on_protocol['Other'] += 1
            output = f"[Other Protocol] {src} -> {dst}"
       

    else:
        packet_count_based_on_protocol["Other"] += 1
        output = "[Other Non-IP Packet]"

    print(output)
    output_to_a_file.append(output)
    packet_log.append(packet)

    anomalies = packet_anomally_hunter(packet, state)

    for anomaly in anomalies:
        print(anomaly)
        output_to_a_file.append(anomaly)



def packet_anomally_hunter(packet, state):

    def update_scan_tracking(packet, state, anomalies, now):
        if IP not in packet:
            return
        
        if TCP not in packet and UDP not in packet:
            return
        
        src = packet[IP].src
        dst = packet[IP].dst

        if TCP in packet:
            dport = packet[TCP].dport
        else:
            dport = packet[UDP].dport

        window = 10
        dq = state["scan_activity_per_src"][src] # יוצר אובייקט בתוך הדיפולט דיקט של סקאן אקטיביטי לכל סורס כדי לעדכן בהמשך את כמויות הייעדים והפורטים שהמקור ניגש אליהם בחלון זמן
        dq.append((now, dst, dport))

        while dq and now - dq[0][0] > window:
            dq.popleft()

        unique_dst_ips = {entry[1] for entry in dq}
        unique_ports = {entry[2] for entry in dq}

        if len (unique_dst_ips) >= 10:
            anomalies.append(f"[!] Scan suspicion: {src} contacted {len(unique_dst_ips)} unique destination IPs in {window}s")

        if len(unique_ports) >= 15:
            anomalies.append(f"[!] Port scan suspicion: {src} contacted {len(unique_ports)} unique ports in {window}s")


    def update_icmp_tracking(packet, state, anomalies, now):
        if IP not in packet or ICMP not in packet:
            return
        
        src = packet[IP].src
        window = 5
        dq = state["icmp_times_per_src"][src] # יוצר אובייקט סורס בתוך הדיפולט דיקט בערך הזה של סטייט כדי לעדכן בו את הטטים סטמפ ואז נמדוד כמות של תקשורת איי סי םא פי בהתאם לזמן
        dq.append(now)

        while dq and now - dq[0] > window:
            dq.popleft()

        if len(dq) >= 20:
            anomalies.append(f"[!] ICMP burst: {src} sent {len(dq)} ICMP packets in {window}s")

    def update_dns_tracking(packet, state, anomalies, now):
        if IP not in packet or DNS not in packet or DNSQR not in packet:
            return
        
        src = packet[IP].src
        qname = packet[DNSQR].qname.decode(errors="ignore") if isinstance(packet[DNSQR].qname, bytes) else str(packet[DNSQR].qname)

        window = 60
        dq = state["dns_queries_per_src"][src] # יוצר אובייקט סורס בתוך הדיפולט דיקט והולך לערוך עבור כל סורס את כמות הפקטות די אן אס שהוא שולח או את אורך השאילתות די אן אס שהוא שולח
        dq.append((now, qname))

        while dq and now - dq[0][0] > window:
            dq.popleft()

        if len(dq) >= 30:
            anomalies.append(f"[!] High DNS activity: {src} sent {len(dq)} DNS queries in {window}s")

        if len(qname) >= 50:
            anomalies.append(f"[!] Suspicious long DNS query: {src} -> {qname}")


    def update_throughput_tracking(packet, state, anomalies, now):
        packet_size = len(packet)
        window = 5

        global_dq = state["global_throughput_window"] # פה אני הולך לעדכן כל פעם את הגודל ואת הזמן
        global_dq.append((now, packet_size))

        while global_dq and now - global_dq[0][0] > window:
            global_dq.popleft()

        global_bytes = 0
        for entry in global_dq:
            global_bytes += entry[1]

        global_bps = global_bytes / window

        if global_bps >= 50000:
            anomalies.append(f"[!] High throughput (global): {global_bps:.2f} bytes/sec over last {window}s")
        
        if IP in packet:
            src = packet[IP].src
            src_dq = state["throughput_per_src"][src] # זה אותו עדכון אבל הפעם לכל סורס כמה ביטים לשנייה
            src_dq.append((now, packet_size))

            while src_dq and now - src_dq[0][0] > window:
                src_dq.popleft()
            
            src_bytes = 0
            for entry in src_dq:
                src_bytes += entry[1]
            
            src_bps = src_bytes / window

            if src_bps >= 30000:
                anomalies.append(f"[!] High throughput from {src}: {src_bps:.2f} bytes/sec over last {window}s") 



    def get_top_talkers(state, top_n=3):
        sent_sorted = sorted(state["bytes_sent_per_ip"].items(), key=lambda x: x[1], reverse=True)[:top_n] #כאמור הבייטים נשלחים לסורס ולדסט מחושבים בפוקנציה של ההאנדל פאקט ופה אנחנו נגדיר גודל הכי גדול כל מספר פקטות או זמן נתון והפוקנציה הזאת הגדולה יותר שהפונקתציה הזאת בתוכה מולכת בתוך האנדל פאקט
        recv_sorted = sorted(state["bytes_received_per_ip"].items(), key=lambda x: x[1], reverse=True)[:top_n]
        return sent_sorted, recv_sorted
    
    #אחרי הגדרות כל החוקים של האנומליות אני מפעיל את הפונקציה הראשית
    anomalies = []
    now = time.time()

    # חוקים שדורשים חישובים
    update_scan_tracking(packet, state, anomalies, now) # גישה להרבה כתובות או פורטים שונים
    update_icmp_tracking(packet, state, anomalies, now) # תקשורת ICMP חריגה
    update_dns_tracking(packet, state, anomalies, now) # תקשורת DNS חריגה או שמות שאילתות חריגים באורך
    update_throughput_tracking(packet, state, anomalies, now) # כמות חריגה של מספר תעבורה בביטים לשנייה

    # חוקים סטטיים

    # SYN packet detection
    if IP in packet and TCP in packet:
        flags = packet[TCP].flags

        if flags == 0x02:
            anomalies.append(
                f"[!] TCP SYN packet observed, potentially connection TCP connection attempt: {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}"
            )

    # ICMP ping detection

    if IP in packet and ICMP in packet:
        if packet[ICMP].type == 8:
            anomalies.append(
            f"[!] ICMP Echo Request detected, could potentially be ping for ping sweep or recon: {packet[IP].src} -> {packet[IP].dst}"
        )


    # Long DNS query

    if DNS in packet and DNSQR in packet:
        qname = packet[DNSQR].qname
        qname = qname.decode(errors="ignore") if isinstance(qname, bytes) else str(qname)

        if len(qname) > 40:
            anomalies.append(
                f"[!] Suspicious long DNS query detected could potentailly lead to DNS tunneling or Data exfiltration: {qname}"
            )


    # TCP NULL Scan
    if IP in packet and TCP in packet:
        if packet[TCP].flags == 0:
            anomalies.append(
                f"[!] TCP NULL scan detected: {packet[IP].src} -> {packet[IP].dst}:{packet[TCP].dport}"
            )


    # TCP Xmas Scan

    if IP in packet and TCP in packet:
        flags = packet[TCP].flags

        if flags & 0x29 == 0x29:  # FIN + PSH + URG
            anomalies.append(
                f"[!] TCP Xmas scan detected: {packet[IP].src} -> {packet[IP].dst}:{packet[TCP].dport}"
            )

    for anomaly in anomalies:
        state["observations"].append({
            "timestamp": now,
            "message": anomaly

        })

    return anomalies

def save_to_pcap(file_name_and_path, packet_log):
    wrpcap(file_name_and_path, packet_log)
    print(f"[+] Packets saved to {file_name_and_path}")



def print_banner():
    banner = r"""
 █████╗ ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗███████╗██████╗
██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗
███████║██║  ██║██║   ██║███████║██╔██╗ ██║██║     █████╗  ██║  ██║
██╔══██║██║  ██║╚██╗ ██╔╝██╔══██║██║╚██╗██║██║     ██╔══╝  ██║  ██║
██║  ██║██████╔╝ ╚████╔╝ ██║  ██║██║ ╚████║╚██████╗███████╗██████╔╝
╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═════╝

██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗
██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝
██████╔╝███████║██║     █████╔╝ █████╗     ██║   
██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║   
██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║   
╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   

███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗ 
██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝

                Advanced Packet Sniffer
---------------------------------------------------------
    Real-time network analysis & anomaly detection tool
    for packet inspection and traffic monitoring on
    your desired Network Interface Card.

    Made by: Shachar Levi Friedman
---------------------------------------------------------
    """
    print(banner)

def loading_spinner(text="Initializing"):
    spinner = ["|", "/", "-", "\\"]

    for i in range(25):
        sys.stdout.write(f"\r{text}... {spinner[i % len(spinner)]}")
        sys.stdout.flush()
        time.sleep(0.08)


    sys.stdout.write("\r" + " " * 50 + "\r")


def main():
    print_banner()
    loading_spinner("Starting")

    parser = argparse.ArgumentParser(description="POC Advanced Packet Sniffer")

    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Network interface to sniff on. If not provided, the script will auto-select the most active interface"


    )
   
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 for unlimited)"
    )

    parser.add_argument(
        "-f", "--filter",
        type = str,
        default="",
        help = "BPF filter string (e.g. 'tcp','udp', 'port 53'...)"
        
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        default="packets.pcap",
        help="Output PCAP file path"
    )

    args = parser.parse_args()

    interface = args.interface if args.interface else pick_active_interfaces()
    state = init_state()

    if not interface:
        print("[-] Could not determine a valid interface")
        return
    
    try:
        print(f"[+] Starting packet sniffing on interface {interface}")
        print(f"    Filter: {args.filter if args.filter else 'None'}")

        sniff(
            iface = interface,
            filter = args.filter if args.filter else None,
            count = args.count,
            prn = lambda pkt: handle_pkt(pkt,state),
            store = False

        )


    except KeyboardInterrupt:
        print("\n[!] Sniffing interrupted by user")

    except Exception as e:
        print(f"[-] Error: {e}")

    finally:
        if state["packet_log"]:
            save_to_pcap(args.output, state["packet_log"])

        print("\n[+] Capture finished")
        print(f"    Total packets: {state['total_packets']}")
        print(f"    Total bytes: {state['total_bytes']}")
        print(f"    Observations: {len(state['observations'])}")

        print("\n[Packet Statistics]")
        for protocol, count in sorted(
                state["packet_count_based_on_protocol"].items(),
                key=lambda x: x[1],
                reverse=True):
            print(f" - {protocol}: {count}")

if __name__ == "__main__":
    main()