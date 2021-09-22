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
BLOCK_SIZE = 16
def recoverSecret():
    prefix_known_length = 26 #The known length of the message that preceeds the secret part
    token = bytearray.fromhex(getAuthToken())
    iv = token[0:16]
    token = token[16:] #First 16 bytes are IV
    recovered_plaintext = ""
    for b in range(1, int(ceil(len(token)-prefix_known_length)/BLOCK_SIZE + 1)):
        token_copy = token[:]
        # token[len[token]-(b*BLOCK_SIZE):len(token)-((b-1)*BLOCK_SIZE)]
        prev_block_start = len(token)-(b*BLOCK_SIZE)-BLOCK_SIZE-1
        for i in range(15, -1, -1):
            for j in range(256):
                token_copy[prev_block_start + i] = j
                result = getQuote((iv + token_copy).hex())
                if("No quote for you!" in result.text): #Correct bit found  
                    recovered_plaintext += chr(j)
                    print(chr(j))
                    break
    # for i in range(len(token) - BLOCK_SIZE, prefix_known_length - BLOCK_SIZE, -1): #Recover secret message
    #     for j in range(256):
    #         token[i] = j
    #         result = getQuote((iv + token).hex())
    #         if("No quote for you!" in result.text): #Correct bit found
    #             recovered_plaintext += chr(j)
    #             print(chr(j))
    #             break #Correct value found - continue
    return recovered_plaintext[::-1]

    
def paddingAttack(stringToAdd):
    for i in range(len(stringToAdd)):
        print(i)

recoverSecret()






