from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap


def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}")

        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Segment: {tcp_layer.sport} -> {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP Datagram: {udp_layer.sport} -> {udp_layer.dport}")
        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            print(f"ICMP Packet: Type {icmp_layer.type}, Code {icmp_layer.code}")


def start_sniffing(interface, packet_count):
    print(f"Starting sniffer on interface {interface}")
    packets = sniff(iface=interface, prn=packet_callback, count=packet_count)
    return packets


interface = "eth0"
packet_count = 5

captured_packets = start_sniffing(interface, packet_count)

wrpcap('captured_packets.pcap', captured_packets)
