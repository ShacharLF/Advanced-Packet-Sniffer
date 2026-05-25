# Advanced-Packet-Sniffer


Advanced Packet Sniffer

A Proof-of-Concept (POC) advanced packet sniffer and lightweight network anomaly detector written in Python using Scapy.

The tool captures live network traffic, parses packets across multiple layers, tracks traffic statistics in real time, and detects suspicious activity patterns such as scans, ICMP bursts, unusual DNS behavior, and high throughput traffic.

Features
Live packet sniffing
Automatic network interface selection
Manual interface selection support
Protocol parsing:
Ethernet
ARP
IP
TCP
UDP
ICMP
DNS
Real-time packet logging
PCAP export support
Traffic statistics collection
Basic anomaly detection engine
BPF filtering support
Command-line interface
Detection Capabilities

The current POC version includes detection logic for:

Reconnaissance / Scanning
TCP SYN packet detection
TCP NULL scan detection
TCP Xmas scan detection
Port scan behavior
Multi-host scan behavior
ICMP ping sweep behavior
DNS Monitoring
High DNS query volume
Suspiciously long DNS queries
Potential DNS tunneling indicators
Throughput Monitoring
High bandwidth usage per source
Global throughput spikes
How It Works

The sniffer captures packets using Scapy and processes every packet through a custom analysis pipeline.

For each packet the tool:

Parses packet layers
Updates traffic statistics
Stores metadata
Runs anomaly detection rules
Prints packet summaries and alerts in real time

The anomaly engine uses:

Sliding time windows
Stateful tracking
Per-IP statistics
Traffic heuristics
Installation
Requirements
Python 3.9+
Npcap installed (Windows)
Administrator privileges
Install Dependencies
pip install scapy
Windows Requirement

This project requires:

Npcap
WinPcap compatible mode enabled during installation

Download:

https://npcap.com/
Usage
Basic Run
python Advanced_Packet_Sniffer.py

The tool will:

Automatically select the most active network interface,

Start sniffing traffic,

Print packets and alerts live,

Command Line Arguments,

Capture Specific Number of Packets,

python Advanced_Packet_Sniffer.py -c 100,

Use Specific Interface,

python Advanced_Packet_Sniffer.py -i "Intel(R) Ethernet Connection",

Apply BPF Filter,

Only TCP traffic,

python Advanced_Packet_Sniffer.py -f tcp,

DNS traffic,

python Advanced_Packet_Sniffer.py -f "port 53",

ICMP traffic,

python Advanced_Packet_Sniffer.py -f icmp,

Save Output PCAP,

python Advanced_Packet_Sniffer.py -o capture.pcap,

Full Example -

"python Advanced_Packet_Sniffer.py -i "Intel(R) Ethernet Connection" -f tcp -c 500 -o traffic.pcap"

Tool Banner

The project includes a custom ASCII startup banner:

ADVANCED PACKET SNIFFER
Description text
Author signature
Optional spinner animation while loading
Example Output
[TCP] 192.168.1.15:53122 -> 142.250.185.14:443

[!] TCP SYN packet observed, potentially connection TCP connection attempt:
192.168.1.15:53122 -> 142.250.185.14:443
Current Limitations

This project is currently a POC (Proof of Concept).

Some limitations include:

Rule engine is heuristic-based
No GUI
No packet reassembly
No flow tracking
No machine learning
Limited protocol coverage
Limited evasion resistance
Basic thresholding logic
Minimal performance optimization
Future Improvements

Possible future features:

Dynamic rule engine
JSON/YAML rule configuration
Signature-based detection
Machine learning anomaly detection
Web dashboard / GUI
Multi-threaded packet processing
Session reconstruction
GeoIP enrichment
Threat intelligence integration
SIEM integration
Logging system
Alert severity scoring
PCAP replay mode
Plugin architecture
Linux optimization with AF_PACKET
Packet stream visualization
Export to JSON/CSV
Detection tuning profiles
Technologies Used
Python
Scapy
Npcap
argparse
collections
subprocess
JSON
Stateful traffic analysis
Educational Purpose

This project was created for:

Cybersecurity learning
Network protocol analysis
Detection engineering practice
Traffic analysis research
Blue team experimentation
Author

Made by: Shachar_Levi
