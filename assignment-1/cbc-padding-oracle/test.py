# from Crypto.Cipher import AES
# key = b"0000111122223333"
# iv = b"aaaabbbbccccdddd"
# cipher = AES.new(key, AES.MODE_CBC, iv)
# a = b"This simple sentence is forty-seven bytes long."
# ciphertext = cipher.encrypt(a + chr(1).encode())
# mod = ciphertext[0:31] + b"\xff" + ciphertext[32:]
# print(ciphertext.hex())
# print(mod.hex())

# cipher = AES.new(key, AES.MODE_CBC, iv)
# print(cipher.decrypt(ciphertext).hex())
# cipher = AES.new(key, AES.MODE_CBC, iv)
# print(cipher.decrypt(mod).hex())
import sys
from pador import encr, decr
a = "This sentence cleaarly says I'M A LOSER."
original = encr(a.encode())
# # print(original)
# for i in range(256):
#     mod = original[0:31] + i.to_bytes(1, byteorder=sys.byteorder) + original[32:]
#     if(decr(mod) != "PADDING ERROR"):
#         print(f"{i} is correctly padded!")

prefix = original[0:16] + b"AAAAAAAAAAAAAAA"
for i in range(256):
    mod = prefix + i.to_bytes(1, byteorder=sys.byteorder) + original[32:]
    if(decr(mod) != "PADDING ERROR"):
        print(f"{i} is correctly padded")

def cbc_oracle_padding_attack(stringToAdd):
    for i in range(len(stringToAdd)):
        print(i)





