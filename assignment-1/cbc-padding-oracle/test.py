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
from numpy import byte, ceil
import sys
from py_linq import py_linq
BLOCK_SIZE = 16
def recoverSecret():
    prefix_known_length = 0 #The known length of the message that preceeds the secret part
    token = bytearray.fromhex(getAuthToken())
    print(token.hex())
    # iv = token[0:16]
    # token = token[16:] #First 16 bytes are IV
    recovered_plaintext = ""
    for b in range(1, int(ceil(len(token)-prefix_known_length)/BLOCK_SIZE + 1)):
        prev_block_start = len(token)-(b*BLOCK_SIZE)-BLOCK_SIZE-1
        recovered_block = bytearray()
        padding = 0x01
        for i in range(BLOCK_SIZE-1, -1, -1):
            token_copy = token[:]
            for j in range(padding - 1): #Use new padding for existing recovered bytes
                token_copy[prev_block_start + BLOCK_SIZE - j] = token_copy[prev_block_start + BLOCK_SIZE - j] ^ recovered_block[j] ^ padding
            byte_recovered = False
            for j in range(256):
                if(j == 0x01):
                    continue
                original_value = token_copy[prev_block_start + i + 1]
                token_copy[prev_block_start + i + 1] = token_copy[prev_block_start + i + 1] ^ j ^ padding
                # to_test = (iv + token_copy)[prev_block_start+len(iv)+1:prev_block_start+len(iv)+2*BLOCK_SIZE+1].hex()
                to_test = token_copy[prev_block_start+1:prev_block_start+1+2*BLOCK_SIZE].hex()
                result = getQuote(to_test)
                if("No quote for you!" in result): #Correct byte found 
                    print(to_test.upper())
                    recovered_block = recovered_block + j.to_bytes(1, sys.byteorder)
                    recovered_plaintext += chr(j)
                    print(f"Found {len(recovered_block)} bytes: {recovered_block[::-1].hex()}")
                    byte_recovered = True
                    break
                else:
                    token_copy[prev_block_start + i + 1] = original_value
            padding += 0x01
            if(not byte_recovered):
                return ""
    return recovered_plaintext[::-1]

def split_len(seq, length):
    """
    Splits hex string in chunks of length
    :param seq: hex string
    :param length: length of desired chunks
    :return: hex string splitted
    """
    return [seq[i : i + length] for i in range(0, len(seq), length)]
    
def attack_block(prevBlock, block):
    padding = 0x01
    bytes_recovered = bytearray(len(block))
    num_bytes_recovered = 0
    for b in reversed(range(0, len(block))): #Iterate over all bytes
        byteFound = False
        for i in range(256):
            # if(i == 0x01):
            #     continue
            prevBlockCopy = bytearray(len(block))
            prevBlockCopy[:] = prevBlock[:]
            for br in reversed(range(len(prevBlock) - num_bytes_recovered, len(prevBlock))): #Iterate over discovered bytes
                prevBlockCopy[br] = prevBlockCopy[br] ^ padding ^ bytes_recovered[br]
            prevBlockCopy[b] = prevBlockCopy[b] ^ padding ^ i
            result = getQuote((prevBlockCopy + block).hex())
            print(result)
            if(not "incorrect" in result):
                num_bytes_recovered += 1
                bytes_recovered[b] = i
                byteFound = True
                break
        if(not byteFound):
            raise Exception(f"Unable to find byte in position {b}!") 
        padding += 0x01
    return bytes_recovered
                    

from Crypto.Util.Padding import pad
def paddingAttack(token, knownText, desiredText):
    desiredTextPadded = pad(desiredText, BLOCK_SIZE)
    knownTextPadded = pad(knownText, BLOCK_SIZE)
    token_blocks = split_len(token, BLOCK_SIZE)
    zeroing_blocks = list()
    for i in range(len(token_blocks)):
        zeroing_blocks.append(bytearray())
    desired_text_blocks = split_len(desiredTextPadded, BLOCK_SIZE)
    known_text_blocks = split_len(knownTextPadded, BLOCK_SIZE)
    for b in reversed(range(1, len(token_blocks))):
        if(b == len(token_blocks)-1):                 #Zeroing vector known
            for i in range(BLOCK_SIZE):
                token_blocks[b-1][i] = token_blocks[b-1][i] ^ known_text_blocks[b-1][i] ^ desired_text_blocks[b-1][i]
            continue 
        zeroing_blocks[b-1] = attack_block(token_blocks[b-1], token_blocks[b])
        for i in range(BLOCK_SIZE):
            token_blocks[b-1][i] = token_blocks[b-1][i] ^ zeroing_blocks[b-1][i] ^ desired_text_blocks[b-1][i]
    quote = getQuote(b''.join(token_blocks).hex())
    print(b''.join(token_blocks).hex())
    # '6d5402774fa1b35430aa745b422b2611a73f0123bd175179598faabb5e7483dece594bad3014703a9fff8920adfa53f10476e1cc341325e2130eae2a7dfca0a8cbdcb1090d820e7c6131690b561c971fd688783dfcd92af2f70eb5e9a6972ff79dafd615c3d4df4e13fe959387c79905'
    return quote
    


# secret = recoverSecret()
token = bytearray.fromhex(getAuthToken())
knownText = 'You never figure out that "I should have used authenticated encryption because ...". :)'
secret = "I should have used authenticated encryption because ..."
stringToAdd = ' plain CBC is not secure!'
quote = paddingAttack(token, knownText.encode(), (secret + stringToAdd).encode())
print(quote)







