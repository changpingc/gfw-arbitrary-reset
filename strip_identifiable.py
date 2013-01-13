#!/usr/bin/env python

from scapy.all import *
import sys


"""
Strips IP addresses in an OpenVPN (TCP) pcap dump.
Server's IP -> 1.1.1.1
Client's IP -> 2.2.2.2
"""

if len(sys.argv) != 4:
    print "Usage: ", sys.argv[0], "<recorded server ip>", "<input dump>", "<output dump>"
    sys.exit(0)
else:
    server_ip = sys.argv[1]
    in_f = sys.argv[2]
    out_f = sys.argv[3]


pkts = rdpcap(in_f)
stripped = []
for pkt in pkts:
    ip = pkt[IP]
    sender = ""
    if ip.src == server_ip:
        ip.src = "1.1.1.1"
        ip.dst = "2.2.2.2"
        ip[TCP].sport = 1194
        del ip.chksum
        del pkt[TCP].chksum
    else:
        ip.dst = "1.1.1.1"
        ip.src = "2.2.2.2"
        ip[TCP].dport = 1194
        del ip.chksum
        del pkt[TCP].chksum

    stripped.append(ip)

wrpcap(out_f, stripped)
print "Processed", len(stripped), "packets."
