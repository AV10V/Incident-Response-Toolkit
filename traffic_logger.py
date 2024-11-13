#!/usr/bin/env python3

import argparse
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

# Display header and instructions to run from the console
"""
### Incident-Response-Toolkit: Network Traffic Logger ###
### Usage: sudo python3 traffic_logger.py --interface <interface> ###
### Example: sudo python3 traffic_logger.py --interface eth0 ###
### Author: AV10V ###
"""

def log_packet(packet):
    """Log packet details to a file."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other"
        log_entry = f"[{datetime.now()}] {proto} - Source: {src_ip} -> Destination: {dst_ip}"
        
        with open("network_log.txt", "a") as log_file:
            log_file.write(log_entry + "\n")
        print(log_entry)

def main():
    parser = argparse.ArgumentParser(description="Log network traffic on a specific interface.")
    parser.add_argument("--interface", "-i", required=True, help="Network interface to monitor (e.g., eth0)")

    args = parser.parse_args()
    
    print(f"[*] Starting network traffic logger on {args.interface}")
    sniff(iface=args.interface, prn=log_packet, store=0)

if __name__ == "__main__":
    main()
