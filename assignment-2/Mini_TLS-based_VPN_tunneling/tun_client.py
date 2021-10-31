#!/usr/bin/python3

import fcntl
import struct
import os
import ssl
import pprint
from scapy.all import *

SERVER_IP = "10.0.2.15"
SERVER_PORT = 9090

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'client%d', (IFF_TUN | IFF_NO_PI))
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)
print("tun interface created...")

# Get the interface name
ifname = ifname_bytes.decode('UTF-8') [:16].strip('\x00')
print("Interface Name: {}".format(ifname))

# Setting up the tun0 interface
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("sudo ip route add 192.168.60.0/24 dev {} via 192.168.53.99".format(ifname))
print("Interface is set up...")
# Create udp socket
sock = socket.socket(socket.AF_INET)

# Wrap in SSL/TLS
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations(os.getcwd() + '/cert.pem')

sslSock = context.wrap_socket(sock, server_hostname=SERVER_IP)
sslSock.connect((SERVER_IP, SERVER_PORT))

cert = sslSock.getpeercert()
pprint.pprint(cert)

while True:
	# this will block until at least one interface is ready
	ready, _, _ = select.select([sslSock, tun], [], [])
	for fd in ready:
		if fd is sock:
			data, (ip, port) = sslSock.recv(2048)
			pkt = IP(data)
			print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
			os.write(tun, bytes(pkt))

		if fd is tun:
			packet = os.read(tun, 2048)
			pkt = IP(packet)
			print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
			sslSock.send(packet)
