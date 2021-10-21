import socket as soc
import ipaddress
import secrets
from login import login
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from icmp import send 
import os 
def encrypt(key, data) -> bytes :
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(pad(data, 16))
    return [nonce, ciphertext, tag]

if(not login()):
    print("Application terminating")
    exit()

dir_path = os.path.dirname(os.path.realpath(__file__))
key = bytearray.fromhex(open(f"{dir_path}/key.txt").read())

socket = soc.socket(soc.AF_INET,soc.SOCK_RAW, soc.IPPROTO_ICMP)
print("Welcome to the covert channel")
print("Please enter the desired IP address to communicate with:")
ipEntered = False
while not ipEntered:
    ip = input()
    try:
        ip = ipaddress.ip_address(ip)
        ipEntered = True
    except:
        print("Entered IP address was invalid. Try again")


print("Type in the messages to send to the server and press enter to send")
print("Type 'exit' and press enter to exit the program")

msg = ""
while msg != "exit":
    msg = input()
    data_encrypted = encrypt(key, msg.encode())
    send(socket, ip.exploded, b''.join(data_encrypted))
    
