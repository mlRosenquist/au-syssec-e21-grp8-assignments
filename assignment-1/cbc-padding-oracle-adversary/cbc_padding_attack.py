from numpy import ceil
import sys
from requests.sessions import session
import requests
BLOCK_SIZE = 16
url = 'https://cbc.syssec.lnrd.net/'

def getAuthToken() -> str:
    """
    Call endpoint defined in url
    :return: cipher from endpoint in a hex string
    """
    session = requests.session()
    session.get(url)
    cookies = session.cookies.get_dict()
    return cookies['authtoken']

def getQuote(token) -> str:
    cookies = {'authtoken': token}
    r = requests.get(url+'/quote', cookies=cookies)
    return r.text
def recoverSecret():
    prefix_known_length = 0 #The known length of the message that preceeds the secret part
    token = bytearray.fromhex(getAuthToken())
    recovered_plaintext = ""
    for b in range(1, int(ceil(len(token)-prefix_known_length)/BLOCK_SIZE + 1)): #Iterate over all bytes
        prev_block_start = len(token)-(b*BLOCK_SIZE)-BLOCK_SIZE-1
        recovered_block = bytearray()
        padding = 0x01
        for i in range(BLOCK_SIZE-1, -1, -1): #Iterate backwards over block
            token_copy = token[:] #Copy token
            for j in range(padding - 1): #Use new padding for existing recovered bytes
                token_copy[prev_block_start + BLOCK_SIZE - j] = token_copy[prev_block_start + BLOCK_SIZE - j] ^ recovered_block[j] ^ padding
            byte_recovered = False
            for j in range(256):
                if(j == 0x01):
                    continue
                original_value = token_copy[prev_block_start + i + 1]
                token_copy[prev_block_start + i + 1] = token_copy[prev_block_start + i + 1] ^ j ^ padding
                to_test = token_copy[prev_block_start+1:prev_block_start+1+2*BLOCK_SIZE].hex() #Construct token
                result = getQuote(to_test)
                if("No quote for you!" in result): #Correct byte found 
                    recovered_block = recovered_block + j.to_bytes(1, sys.byteorder)
                    recovered_plaintext += chr(j)
                    print(f"Found {len(recovered_block)} bytes: {recovered_block[::-1].hex()}") #print found text and status message
                    byte_recovered = True
                    break
                else:
                    token_copy[prev_block_start + i + 1] = original_value
            padding += 0x01
            if(not byte_recovered): #Early exit if no byte found
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
        if(b == len(token_blocks)-1):                 #Zeroing vector known for the last block
            for i in range(BLOCK_SIZE):
                token_blocks[b-1][i] = token_blocks[b-1][i] ^ known_text_blocks[b-1][i] ^ desired_text_blocks[b-1][i]
            continue 
        print(f"Recovering block {b}")
        zeroing_blocks[b-1] = attack_block(token_blocks[b-1], token_blocks[b])
        print(f"Recovered block {b}")
        for i in range(BLOCK_SIZE):
            #Update block with found zeroing vector and desired plaintext in order to use in next block attack
            token_blocks[b-1][i] = token_blocks[b-1][i] ^ zeroing_blocks[b-1][i] ^ desired_text_blocks[b-1][i] 
    return b''.join(token_blocks).hex()
    

if(len(sys.argv)) != 2:
    raise Exception("Wrong number of arguments")
arg = sys.argv[1]
if(arg == "recoverPlaintext"):
    plainText = recoverSecret()
    with open("plaintext.txt", "wb") as f:
        f.write(plainText)
        f.close()
elif(arg == "subAttack"):
    token = bytearray.fromhex(getAuthToken())
    knownText = 'You never figure out that "I should have used authenticated encryption because ...". :)'
    secret = "I should have used authenticated encryption because ..."
    stringToAdd = ' plain CBC is not secure!'
    validToken = paddingAttack(token, knownText.encode(), (secret + stringToAdd).encode())
    quote = getQuote(validToken)
    with open("validToken.txt", "wb") as f:
        f.write(validToken)
        f.close()
    with open("quote.txt", "wb") as f:
        f.write(quote)
        f.close()
elif(arg == "getQuotes"):
    quotes = []
    for i in range(10):
        token = '741a390d6cd0bc8082e68a8ea0804eabfa56917a4c9499806a0a2c6f0244a426d789a39cb3077ed034591c9dba0facb714e31c82504d32dc7d30d5354acf95dd130adc47a06889f8f8b5069f5f50242f76aa4ccf85a7ff32150cc7c342075ed7594d5b9eb53a6c61a310fbb87b84b933'
        quotes.append(getQuote(token))
    with open("quotes.txt", "wb") as f:
        for q in quotes:
            f.write(q.encode())
        f.close()
else:
    raise Exception("Invalid argument")










