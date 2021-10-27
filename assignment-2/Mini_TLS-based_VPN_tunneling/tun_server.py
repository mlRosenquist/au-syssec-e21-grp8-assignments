#!/usr/bin/python3

import fcntl
from scapy.all import *

# Creating the tun interface
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'ahj%d', (IFF_TUN | IFF_NO_PI))
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)
print("tun interface created...")

# Get the interface name
ifname = ifname_bytes.decode('UTF-8') [:16].strip('\x00')
print("Interface Name: {}".format(ifname))

# Setting up the server0 interface
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
print("Interface is set up...")

# Setting up socket interface
IP_A = "0.0.0.0"
PORT = 9090

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))

print("starting to listen:")
while True:
	# this will block until at least one interface is ready
	ready, _, _ = select.select([sock, tun], [], [])
    	for fd in ready:
        	if fd is sock:
        	    data, (ip, port) = sock.recvfrom(2048)
        	    pkt = IP(data)
        	    print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
        	    os.write(tun, bytes(pkt))
        
		if fd is tun:
        	    packet = os.read(tun, 2048)
        	    pkt = IP(packet)
        	    print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst))
        	    sock.sendto(packet, ("10.0.2.4", 9090))
