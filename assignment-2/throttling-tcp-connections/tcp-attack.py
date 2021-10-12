#!/usr/bin/env python
from scapy.all import *
from scapy.layers.inet import IP, TCP

dport = 22
sport = 59332
srcip = "10.0.2.5"
dstip = "10.0.2.4"
ip=IP(src=srcip, dst=dstip)

syn_filter = lambda r: TCP in r and \
                          r[TCP].sport == sport and\
                          r[IP].src == srcip and \
                          r[TCP].dport == dport and \
                          r[IP].dst == dstip and \
                          r[TCP].flags.syn == 1 and \
                          r[TCP].flags.ack == 0

ack_filter = lambda r: TCP in r and \
                          r[TCP].sport == dport and\
                          r[IP].src == dstip and \
                          r[TCP].dport == sport and \
                          r[IP].dst == srcip and \
                          r[TCP].flags.ack == 1

if __name__ == '__main__':
    print("Awaiting SYN packet")
    pkts = sniff(count=1, lfilter=syn_filter)
    pkts.summary()
    while True:
        print("Awaiting ack packets")
        pkts = sniff(count=1, lfilter=ack_filter)
        pkts.summary()

# scp 20mbfile.txt mlr@10.0.2.4:/home/mlr/files/text.txt
# ssh -p 22 mlr@10.0.2.4