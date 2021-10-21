import socket as soc
from login import login
from hashlib import sha512
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from icmp import receive
import os

def decrypt(key, data) -> bytes :
    nonce = data[0:12]
    tag = data[len(data)-16:len(data)]
    data = data[12:len(data)-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return unpad(cipher.decrypt_and_verify(data, tag), 16)

if(not login()):
    print("Application terminating")
    exit()

dir_path = os.path.dirname(os.path.realpath(__file__))
key = bytearray.fromhex(open(f"{dir_path}/key.txt").read())

serverSocket = soc.socket(soc.AF_INET, soc.SOCK_RAW, soc.IPPROTO_ICMP)
localHost = soc.gethostbyname(soc.gethostname())
serverSocket.bind((localHost, 0))
serverSocket.ioctl(soc.SIO_RCVALL, soc.RCVALL_ON)
print(f"Listening on: {localHost}")
while True:
    data, addr = receive(serverSocket)
    data_decrypted = decrypt(key, data)
    print(f"Received data from address {addr}: {data_decrypted}")
    