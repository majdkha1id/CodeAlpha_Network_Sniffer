# CodeAlpha_Network_Sniffer

This is a network sniffer in Python that captures and analyzes network traffic. It will help you
understand how data flows on a network and how network packets are structured.
This example captures and prints basic packet information.

# Steps 
# Imports:
We import necessary components from scapy.
# Packet Callback Function:
The packet_callback function processes each captured packet and prints its details if it has IP, TCP, or UDP layers.
# Start Sniffing Function:
The start_sniffing function initiates packet sniffing on the specified network interface and captures a given number of packets.
# Configuration:
Set the network interface (interface) and the number of packets to capture (packet_count).
# Start Sniffing: 
Call the start_sniffing function to start capturing packets.
# Save Packets: 
Optionally, the captured packets are saved to a file named captured_packets.pcap.

# Summary
The network sniffer script using scapy is a straightforward yet powerful tool for capturing and analyzing network traffic, making it ideal for network troubleshooting, security monitoring, and educational purposes in a Linux environment.
