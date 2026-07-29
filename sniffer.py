import socket
import struct
import textwrap

# Create raw socket
sniffer = socket.socket(
    socket.AF_INET,
    socket.SOCK_RAW,
    socket.IPPROTO_TCP
)

sniffer.bind(("0.0.0.0", 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

print("Packet Sniffer started...")

def parse_ip_header(data):
    iph = struct.unpack('!BBHHHBBH4s4s', data[:20])

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4

    ttl = iph[5]
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dest_ip = socket.inet_ntoa(iph[9])

    return version, ihl, ttl, protocol, src_ip, dest_ip

def parse_tcp_header(data):
    tcph = struct.unpack('!HHLLBBHHH', data[:20])

    src_port = tcph[0]
    dest_port = tcph[1]
    seq = tcph[2]
    ack = tcph[3]
    offset = (tcph[4] >> 4) * 4

    return src_port, dest_port, seq, ack, offset

while True:
    raw_data, addr = sniffer.recvfrom(65535)

    version, ihl, ttl, protocol, src_ip, dest_ip = parse_ip_header(raw_data)

    if protocol == 6:  # TCP
        tcp_start = ihl
        tcp_data = raw_data[tcp_start:tcp_start+20]
        src_port, dest_port, seq, ack, offset = parse_tcp_header(tcp_data)

        print("\nTCP Packet:")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dest_ip}")
        print(f"Source Port: {src_port}")
        print(f"Destination Port: {dest_port}")
        print(f"Sequence Number: {seq}")
        print(f"Acknowledgement: {ack}")