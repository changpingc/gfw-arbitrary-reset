# suppress scapy IPv6 warning.
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import os
import sys
import socket
import tornado.ioloop
from scapy.all import *
import time
from datetime import timedelta, datetime
from tornadorpc.json import JSONRPCHandler
from tornadorpc import start_server
import subprocess


if "check_output" not in dir(subprocess):  # duck punch it in!
    def f(*popenargs, **kwargs):
        if 'stdout' in kwargs:
            raise ValueError('stdout argument not allowed, it will be overridden.')
        process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
        output, unused_err = process.communicate()
        retcode = process.poll()
        if retcode:
            cmd = kwargs.get("args")
            if cmd is None:
                cmd = popenargs[0]
            raise CalledProcessError(retcode, cmd)
        return output
    subprocess.check_output = f


class DOSRPCHandler(JSONRPCHandler):
    def __init__(self, *args, **kwargs):
        super(DOSRPCHandler, self).__init__(*args, **kwargs)

    def raw_send(self, pkt):
        p = IP(pkt.decode("base64"))
        print p.summary()
        send(p)

    def getpid(self):
        return os.getpid()

    def shell(self, *args, **kwargs):
        kwargs['shell'] = True
        return subprocess.check_output(*args, **kwargs)

    def send(self, ip_options, tcp_options, data):
        tcp = TCP(**tcp_options)
        ip = IP(**ip_options)
        pkt = ip / tcp / data
        self.delayed_send(pkt)
        return pkt.summary()

    def syn(self, src, sport, dst, dport, seq, ttl=64):
        tcp = TCP(sport=sport, dport=dport, flags="S", seq=seq, ack=0)
        ip = IP(src=src, dst=dst, ttl=ttl)
        pkt = ip / tcp
        self.delayed_send(pkt)
        return pkt.summary()

    def synack(self, src, sport, dst, dport, seq, ack, ttl=64):
        tcp = TCP(sport=sport, dport=dport, flags="SA", seq=seq, ack=ack)
        ip = IP(src=src, dst=dst, ttl=ttl)
        pkt = ip / tcp
        send(pkt)
        return pkt.summary()

    def ack(self, src, sport, dst, dport, seq, ack, ttl=64):
        tcp = TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=ack)
        ip = IP(src=src, dst=dst, ttl=ttl)
        pkt = ip / tcp
        self.delayed_send(pkt)
        return pkt.summary()

    def push(self, src, sport, dst, dport, seq, ack, data, ttl=64):
        tcp = TCP(sport=sport, dport=dport, flags="P", ack=ack, seq=seq)
        ip = IP(src=src, dst=dst, ttl=ttl)
        pkt = ip / tcp / bytes(data)
        self.delayed_send(pkt)
        return pkt.summary()

if len(sys.argv) != 2:
    print "Usage: ", sys.argv[0], "<port>"
    print "See README.md or https://github.com/ccp0101/gfw-arbitrary-reset for more detail."
else:
    start_server(DOSRPCHandler, port=int(sys.argv[1]))
