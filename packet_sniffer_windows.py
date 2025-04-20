from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP

# Use L3 socket for sniffing
conf.L3socket = conf.L3socket

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"\n[+] Packet: {ip_layer.src} --> {ip_layer.dst}")
        if packet.haslayer(TCP):
            print(f"    Protocol: TCP | Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"    Protocol: UDP | Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}")

# Start sniffing packets
print("Starting packet capture... (Press CTRL+C to stop)\n")
sniff(filter="ip", prn=process_packet, store=0)