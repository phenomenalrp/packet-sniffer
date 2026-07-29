# Custom Packet Sniffer using Python

## Overview
A basic packet sniffer built using Python raw sockets to capture and analyze TCP/IP packets.

## Features
- Capture live network packets using raw sockets
- Parse IPv4 headers
- Parse TCP headers
- Display source and destination IP addresses
- Display source and destination ports
- Display sequence and acknowledgement numbers

## Technologies Used
- Python 3
- socket
- struct

## Requirements
- Linux (Ubuntu/Kali recommended)
- Python 3
- Root privileges

## Run

```bash
sudo python3 sniffer.py
```

## Sample Output

```
Packet Sniffer started...

TCP Packet:
Source IP: 192.168.1.10
Destination IP: 142.250.xxx.xxx
Source Port: 51544
Destination Port: 443
```

## Learning Outcomes
- Raw socket programming
- TCP/IP packet parsing
- Network traffic analysis
- Low-level networking concepts
