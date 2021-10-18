#Taken from https://github.com/ValentinBELYN/icmplib/blob/454e4c37617e2ea892b2e07df024c3c401d4b29b/icmplib/sockets.py#L125 and modified
from struct import pack, unpack
import socket
from sys import platform

PLATFORM_LINUX   = platform == 'linux'
PLATFORM_MACOS   = platform == 'darwin'
PLATFORM_WINDOWS = platform == 'win32'

ICMP_HEADER_CODE = 47
ICMP_CODE = socket.getprotobyname('icmp')
ICMP_MAX_PAYLOAD_SIZE = 65507

_ICMP_HEADER_OFFSET      = 20
_ICMP_HEADER_REAL_OFFSET = 20

_ICMP_CHECKSUM_OFFSET    = _ICMP_HEADER_OFFSET + 2
_ICMP_PAYLOAD_OFFSET     = _ICMP_HEADER_OFFSET + 8

_ICMP_ECHO_REPLY         = 0

def calc_checksum(data):
    sum = 0
    data += b'\x00'

    for i in range(0, len(data) - 1, 2):
        sum += (data[i] << 8) + data[i + 1]
        sum  = (sum & 0xffff) + (sum >> 16)

    sum = ~sum & 0xffff

    return sum

def create_packet(id, sequence, data: bytes):
    checksum = 0
    header = pack('!2B3H', ICMP_CODE, 0, checksum, id, sequence)
    checksum = calc_checksum(header + data)
    header = pack('!2B3H', ICMP_CODE, 0, checksum, id, sequence)
    return header + data

def send(s: socket.socket, dest_addr, data):
    for i in range(int(((len(data)/ICMP_MAX_PAYLOAD_SIZE)+0.5)) + 1):
        packet = create_packet(
            id=1,
            sequence=i,
            data=data)
        s.sendto(packet, (dest_addr, 0))

def receive(s: socket.socket) -> tuple():
    packet, addr = s.recvfrom(1024)
    if PLATFORM_LINUX:
        packet = b'\x00' * _ICMP_HEADER_OFFSET + packet

    if len(packet) < _ICMP_CHECKSUM_OFFSET:
        return None

    type, code = unpack('!2B', packet[
        _ICMP_HEADER_OFFSET:
        _ICMP_CHECKSUM_OFFSET])

    if type != _ICMP_ECHO_REPLY:
        packet = packet[
            _ICMP_PAYLOAD_OFFSET
            - _ICMP_HEADER_OFFSET
            + _ICMP_HEADER_REAL_OFFSET:]

    if len(packet) < _ICMP_PAYLOAD_OFFSET:
        return None
    return (packet, addr)