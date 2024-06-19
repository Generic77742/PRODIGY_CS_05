from scapy.all import *

captured_packet = sniff(count=1)[0]

source_ip = captured_packet[IP].src
destination_ip = captured_packet[IP].dst
protocol = captured_packet[IP].proto
if TCP in captured_packet:
    protocol = "TCP"
    payload = captured_packet[TCP].payload
elif UDP in captured_packet:
    protocol = "UDP"
    payload = captured_packet[UDP].payload
elif ICMP in captured_packet:
    protocol = "ICMP"
    payload = captured_packet[ICMP].payload
else:
    protocol = "Unknown"
    payload = None

print(f"Source IP: {source_ip}")
print(f"Destination IP: {destination_ip}")
print(f"Protocol: {protocol}")
print(f"Payload: {payload}")