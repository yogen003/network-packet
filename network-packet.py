from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Function to process each captured packet
def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        # Extract source and destination IP
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check for TCP or UDP protocols and extract relevant info
        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            protocol = "Other"
            src_port = None
            dst_port = None
        
        # Print captured packet details
        print(f"Protocol: {protocol}")
        print(f"Source IP: {src_ip}:{src_port if src_port else ''}")
        print(f"Destination IP: {dst_ip}:{dst_port if dst_port else ''}")
        print(f"Payload: {bytes(packet[IP].payload)}\n")
    
# Replace 'wlan0' with your Wi-Fi interface name
sniff(iface="Wi-Fi", filter="ip", prn=packet_callback, store=0)
