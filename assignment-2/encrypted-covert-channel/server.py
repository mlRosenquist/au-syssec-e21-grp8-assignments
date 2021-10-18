import socket as soc
import ipaddress
import struct
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from icmp import receive

def decrypt(key, data) -> bytes :
    nonce = data[0:10]
    tag = data[len(data)-16:len(data)]
    data = data[10:len(data)-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return unpad(cipher.decrypt_and_verify(data, tag), 16)


key = "ELmxKedMDDdRFoquhuqvVSGA6dKtGz36".encode()
serverSocket = soc.socket(soc.AF_INET, soc.SOCK_RAW, soc.IPPROTO_ICMP)
localHost = soc.gethostbyname(soc.gethostname())
serverSocket.bind((localHost, 0))
serverSocket.ioctl(soc.SIO_RCVALL, soc.RCVALL_ON)
print(f"Listening on: {localHost}")
while True:
    data, addr = receive(serverSocket)
    data_decrypted = decrypt(key, data)
    print(f"Received data from address {addr}: {data_decrypted}")
    