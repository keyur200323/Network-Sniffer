import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest
import datetime

# Interface name
iface = 'Wi-Fi'

# Packet lists
pkt_list = []
ip_list = []
tcp_list = []
udp_list = []
http_list = []

# Packet counts
pkt_count = 0
ip_count = 0
tcp_count = 0
udp_count = 0


def sniff_packets(iface):
    scapy.sniff(iface=iface, prn=process_packet, store=False)


def process_packet(packet):
    global pkt_count, ip_count, tcp_count, udp_count

    # Append packet to list
    pkt_list.append(packet)

    # Increment packet count
    pkt_count += 1

    if IP in packet:
        ip_count += 1

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Collect unique IP addresses
        if src_ip not in ip_list:
            ip_list.append(src_ip)
        if dst_ip not in ip_list:
            ip_list.append(dst_ip)

        print(f"IP {packet[IP].src} -> {packet[IP].dst}")

    if TCP in packet:
        tcp_count += 1

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Collect unique TCP ports
        if src_port not in tcp_list:
            tcp_list.append(src_port)
        if dst_port not in tcp_list:
            tcp_list.append(dst_port)

        print(f"TCP {packet[TCP].sport} -> {packet[TCP].dport}")

    if UDP in packet:
        udp_count += 1
        print(f"UDP {packet[UDP].sport} -> {packet[UDP].dport}")

    if HTTPRequest in packet:
        http_list.append(packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode())
        print(f"HTTP {packet[HTTPRequest].Host} {packet[HTTPRequest].Path}")

print("-----------------------------------")

print(f"\nSniffing on {iface}")
sniff_packets(iface)

# Write packets to pcap file
now = datetime.datetime.now()
filename = now.strftime("capture_%Y%m%d_%H%M%S.pcap")
scapy.wrpcap(filename, pkt_list)

# Print summary stats
print("\nSummary Statistics:")
print(f"{'Total Packets':20}{pkt_count}")
print(f"{'TCP Packets':20}{tcp_count}")
print(f"{'UDP Packets':20}{udp_count}")
print(f"{'Total IP Packets':20}{ip_count}")

# Print collected data
print("\nUnique IP Addresses:")
[print(ip) for ip in sorted(ip_list)]

print("\nUnique TCP Ports:")
[print(port) for port in sorted(tcp_list)]

print("\nHTTP Requests:")
[print(url) for url in http_list]