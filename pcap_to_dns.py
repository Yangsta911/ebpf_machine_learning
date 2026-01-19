from scapy.all import rdpcap, DNS, IP, UDP
import pandas as pd

PCAP_FILE = "2013-08-20_capture-win2.pcap"

rows = []

for pkt in rdpcap(PCAP_FILE):
    if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
        continue

    udp = pkt[UDP]

    # Match your eBPF logic exactly
    if udp.sport != 53 and udp.dport != 53:
        continue

    dns = pkt[DNS]

    rows.append({
        "ts": pkt.time,
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "src_port": udp.sport,
        "dst_port": udp.dport,
        "payload_len": len(udp.payload),
        "is_query": int(dns.qr == 0)
    })

df = pd.DataFrame(rows)
df.to_csv("dns_raw.csv", index=False)

print(f"[+] Extracted {len(df)} DNS packets")
