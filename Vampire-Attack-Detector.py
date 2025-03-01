# -*- coding: utf-8 -*-
"""
Created on Sat Mar 1  00:345:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("Vampire Attack Detector")
print(Fore.GREEN+font)

import scapy.all as scapy
import time
from collections import defaultdict

# Dictionary to keep track of the number of requests per IP
request_counter = defaultdict(int)

# Thresholds for detecting vampire attacks
TRAFFIC_THRESHOLD = 100  # Number of packets received from a single IP in 10 seconds

# Function to analyze network packets and detect potential vampire attacks
def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        request_counter[ip_src] += 1
        
        # Check if the IP address has exceeded the threshold
        if request_counter[ip_src] > TRAFFIC_THRESHOLD:
            print(f"[ALERT] Potential Vampire Attack detected from IP: {ip_src}")
        
        # Log for demonstration
        print(f"Packet from {ip_src}, Total Requests: {request_counter[ip_src]}")

# Function to start the packet sniffing
def start_sniffing():
    print("Starting packet sniffing...")
    scapy.sniff(prn=packet_callback, store=0)

# Main function
def main():
    ip_address = input("Enter the IP address you want to monitor (leave empty to monitor all): ").strip()
    
    # If user provides an IP address, filter packets for that IP
    if ip_address:
        print(f"Monitoring traffic for IP address: {ip_address}")
        scapy.sniff(filter=f"host {ip_address}", prn=packet_callback, store=0)
    else:
        print("Monitoring all traffic...")
        start_sniffing()

if __name__ == "__main__":
    main()
