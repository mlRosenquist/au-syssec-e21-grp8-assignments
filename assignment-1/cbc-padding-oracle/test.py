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
# import sys
# from pador import encr, decr
# a = "This sentence cleaarly says I'M A LOSER."
# original = encr(a.encode())
# # print(original)
# for i in range(256):
#     mod = original[0:31] + i.to_bytes(1, byteorder=sys.byteorder) + original[32:]
#     if(decr(mod) != "PADDING ERROR"):
#         print(f"{i} is correctly padded!")

# prefix = original[0:16] + b"AAAAAAAAAAAAAAA"
# for i in range(256):
#     mod = prefix + i.to_bytes(1, byteorder=sys.byteorder) + original[32:]
#     if(decr(mod) != "PADDING ERROR"):
#         print(f"{i} is correctly padded")
from main import getAuthToken, getQuote
from numpy import ceil
import sys
BLOCK_SIZE = 16
def recoverSecret():
    prefix_known_length = 26 #The known length of the message that preceeds the secret part
    token = bytearray.fromhex(getAuthToken())
    iv = token[0:16]
    token = token[16:] #First 16 bytes are IV
    recovered_plaintext = ""
    for b in range(1, int(ceil(len(token)-prefix_known_length)/BLOCK_SIZE + 1)):
        prev_block_start = len(token)-(b*BLOCK_SIZE)-BLOCK_SIZE-1
        recovered_block = bytearray()
        padding = 0x01
        for i in range(BLOCK_SIZE-1, -1, -1):
            token_copy = token[:]
            for j in range(padding - 1): #Use new padding for existing recovered bytes
                token_copy[prev_block_start + BLOCK_SIZE - 1 - j] = token_copy[prev_block_start + BLOCK_SIZE - 1 - j] ^ recovered_block[j] ^ padding
            byte_recovered = False
            for j in range(256):
                token_copy[prev_block_start + i] = token_copy[prev_block_start + i] ^ j ^ padding
                result = getQuote((iv + token_copy).hex())
                if("No quote for you!" in result): #Correct byte found 
                    recovered_block = recovered_block + j.to_bytes(1, sys.byteorder)
                    recovered_plaintext += chr(j)
                    print(chr(j))
                    byte_recovered = True
                    break
            padding += 0x01
            if(not byte_recovered):
                return ""
    return recovered_plaintext[::-1]

    
def paddingAttack(stringToAdd):
    for i in range(len(stringToAdd)):
        print(i)

secret = recoverSecret()
print(secret)






