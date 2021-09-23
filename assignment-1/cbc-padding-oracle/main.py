import sys
import requests
import re
import concurrent.futures

from concurrent.futures import wait
from itertools import cycle
from enum import Enum
from py_linq import py_linq

class OracleStatus(Enum):
    NoPaddingError = 1,
    PaddingError = 2,
    Unknown = 3

class BlockByteStatus:
    oracleStatus : OracleStatus
    block_search_byte : str
    ct_pos : int

url = 'https://cbc.syssec.lnrd.net/'


def getCipher() -> str:
    """
    Call endpoint defined in url
    :return: cipher from endpoint in a hex string
    """
    session = requests.session()
    session.get(url)
    cookies = session.cookies.get_dict()
    return cookies['authtoken']

def call_oracle(hexString):
    """
    Calls oracle to validated padding
    :param hexString:
    :return: OracleStatus enum 
    """
    cookies = {'authtoken': hexString}
    r = requests.get(url+'/quote', cookies=cookies)
    if(r.text == 'No quote for you!' or
            r.text == "'utf-8' codec can't decode byte 0xcc in position 2: invalid continuation byte" or
            r.text == "'utf-8' codec can't decode byte 0xdc in position 2: invalid continuation byte" or
            r.text == "'utf-8' codec can't decode byte 0xdc in position 2: unexpected end of data" or
            r.text == "'utf-8' codec can't decode byte 0xd8 in position 0: unexpected end of data" or
            r.text == "'utf-8' codec can't decode byte 0xb4 in position 2: invalid start byte" or
            "decode" in r.text):
        return OracleStatus.NoPaddingError
    elif(r.text == 'Padding is incorrect.' or r.text == 'PKCS#7 padding is incorrect.'):
        return OracleStatus.PaddingError
    else:
        return OracleStatus.Unknown

def test_validity(error):
    """
    Validates oracles response
    :param error: OracleStatus enum
    :return: 1 if padding error is received else 0
    """
    if error != OracleStatus.PaddingError and error != OracleStatus.Unknown:
        return 1
    return 0

def split_len(seq, length):
    """
    Splits hex string in chunks of length
    :param seq: hex string
    :param length: length of desired chunks
    :return: hex string splitted
    """
    return [seq[i : i + length] for i in range(0, len(seq), length)]


def hex_xor(s1, s2):
    """
    xor two hex strings
    :param s1: hex string
    :param s2: hex string
    :return: xor of s1 and s2
    """
    b = bytearray()
    for c1, c2 in zip(bytes.fromhex(s1), cycle(bytes.fromhex(s2))):
        b.append(c1 ^ c2)
    return b.hex()

def block_search_byte(size_block, i, pos, l):
    """
    Create custom block for the byte we search
    """
    hex_char = hex(pos).split("0x")[1]

    test = (
        "00" * (size_block - (i + 1))
        + ("0" if len(hex_char) % 2 != 0 else "")
        + hex_char
        + "".join(l)
    )
    return (
        "00" * (size_block - (i + 1))
        + ("0" if len(hex_char) % 2 != 0 else "")
        + hex_char
        + "".join(l)
    )

def block_padding(size_block, i):
    """
    Create custom block for padding
    """
    l = []
    for t in range(0, i + 1):
        l.append(
            ("0" if len(hex(i + 1).split("0x")[1]) % 2 != 0 else "")
            + (hex(i + 1).split("0x")[1])
        )
    return "00" * (size_block - (i + 1)) + "".join(l)

def getBlockByte(size_block, i, ct_pos, valide_value, cipher_block, block):
    """
    Validates if a byte is to be included
    Generate hex and calls oracle
    :return: OracleStatus
    """
    if ct_pos != i + 1 or (
            len(valide_value) > 0 and int(valide_value[-1], 16) == ct_pos
    ):
        bk = block_search_byte(size_block, i, ct_pos, valide_value)
        bp = cipher_block[block - 1]
        bc = block_padding(size_block, i)
        tmp = hex_xor(bk, bp)
        cb = hex_xor(tmp, bc).upper()

        up_cipher = cb + cipher_block[block]
        # time.sleep(0.5)

        # we call the oracle, our god
        error = call_oracle(up_cipher)
        status = BlockByteStatus()
        status.oracleStatus = error
        status.block_search_byte = bk
        status.ct_pos = ct_pos
        return status


def getPlainText() -> str:
    cipher = getCipher().upper()
    size_block = 16
    found = False
    valide_value = []
    result = []
    len_block = size_block * 2
    cipher_block = split_len(cipher, len_block)

    for block in reversed(range(1, len(cipher_block))):
        if len(cipher_block[block]) != len_block:
            print("[-] Abort length block doesn't match the size_block")
            break
        print("[+] Search value block : ", block, "\n")
        # for each byte of the block
        for i in range(0, size_block):
            # test each byte max 255
            """
            Test the correct values
            Done concurrently to utilize more processing power and memory
            Can be tweaked on the concurrent_tasks value
            """
            blockByteResults = py_linq.Enumerable([])
            futures = []
            searching = True
            concurrent_tasks = 8 * 7
            batch_number = 0
            while searching:
                with concurrent.futures.ProcessPoolExecutor(max_workers=concurrent_tasks) as pool:
                    futures = [pool.submit(getBlockByte, size_block, i, ct_pos, valide_value, cipher_block, block) for
                               ct_pos in range(batch_number * concurrent_tasks,
                                               batch_number * concurrent_tasks + concurrent_tasks)]
                    wait(futures)
                for fut in futures:
                    blockByteResults.append(fut.result())
                if (blockByteResults.any(lambda res: res is not None and test_validity(res.oracleStatus))):
                    searching = False
                batch_number += 1

            if (blockByteResults.any(lambda res: res is not None and test_validity(res.oracleStatus))):
                blockByteRes = blockByteResults.first(lambda res: res is not None and test_validity(res.oracleStatus))

                found = True

                # data analyse and insert in rigth order
                value = re.findall("..", blockByteRes.block_search_byte)
                valide_value.insert(0, value[size_block - (i + 1)])

                bytes_found = "".join(valide_value)
                if (
                        i == 0
                        and int(bytes_found, 16) > size_block
                        and block == len(cipher_block) - 1
                ):
                    print(
                        "[-] Error decryption failed the padding is > "
                        + str(size_block)
                    )
                    sys.exit()

                print(
                    "\033[36m" + "\033[1m" + "[+]" + "\033[0m" + " Found",
                    i + 1,
                    "bytes :",
                    bytes_found,
                )
                print("")

            if found == False:
                # lets say padding is 01 for the last block (the padding block)
                if len(cipher_block) - 1 == block and i == 0:
                    value = re.findall("..", blockByteRes.block_search_byte)
                    valide_value.insert(0, "01")

                else:
                    print("\n[-] Error decryption failed")
                    result.insert(0, "".join(valide_value))
                    hex_r = "".join(result)
                    if len(hex_r) > 0:
                        print("[+] Partial Decrypted value (HEX):", hex_r.upper())
                        padding = int(hex_r[len(hex_r) - 2: len(hex_r)], 16)
                        print(
                            "[+] Partial Decrypted value (ASCII):",
                            bytes.fromhex(hex_r[0: -(padding * 2)]).decode(),
                        )
                    sys.exit()
            found = False

        result.insert(0, "".join(valide_value))
        valide_value = []

    print("")
    hex_r = "".join(result)
    print("[+] Decrypted value (HEX):", hex_r.upper())
    padding = int(hex_r[len(hex_r) - 2: len(hex_r)], 16)
    decoded = bytes.fromhex(hex_r[0: -(padding * 2)]).decode()
    return decoded


def getBlockByte2(size_block, i, value, found_values_block, result, block):
    """
    Validates if a byte is to be included
    Generate hex and calls oracle
    :return: OracleStatus
    """
    bk = block_search_byte(size_block, i, value, found_values_block)
    bc = block_padding(size_block, i)
    tmp = hex_xor(bk, bc)
    up_cipher = tmp + result[block]
    if(len(up_cipher) % 16 != 0):
        x = 1+1
    # we call the oracle, our god
    error = call_oracle(up_cipher)
    status = BlockByteStatus()
    status.oracleStatus = error
    status.block_search_byte = bk
    status.ct_pos = value
    return status

def buildCipherText(secret, suffix):
    global value
    size_block = 16
    len_block = size_block * 2

    desired_text_str = secret + suffix
    desired_text_hex = desired_text_str.encode('utf-8').hex() + "10101010101010101010101010101010"
    desired_text_bytes = bytearray.fromhex(desired_text_hex)
    desired_text_bytes_split = split_len(desired_text_hex, len_block)

    found_values_block = []
    result = split_len((bytearray(b'\x00') * size_block * 6 + bytearray(b'\x41') * size_block ).hex(), len_block)
    cipher_block = split_len((bytearray(b'\x00') * size_block * 6 + bytearray(b'\x41') * size_block).hex(), len_block)

    for block in reversed(range(1, len(cipher_block))):
        print("[+] Search value block : ", block, "\n")

        for i in range(0, size_block):
            print("[+] Search Byte : ", i, "\n")
            blockByteResults = py_linq.Enumerable([])
            futures = []
            searching = True
            concurrent_tasks = 8 * 4
            batch_number = 0
            while searching:
                with concurrent.futures.ProcessPoolExecutor(max_workers=concurrent_tasks) as pool:
                    futures = [pool.submit(getBlockByte2, size_block, i, value, found_values_block, result, block) for
                               value in range(batch_number * concurrent_tasks,
                                               batch_number * concurrent_tasks + concurrent_tasks)]
                    wait(futures)
                for fut in futures:
                    blockByteResults.append(fut.result())
                if (blockByteResults.any(lambda res: res is not None and test_validity(res.oracleStatus))):
                    searching = False
                batch_number += 1

            if (blockByteResults.any(lambda res: res is not None and test_validity(res.oracleStatus))):
                blockByteRes = blockByteResults.first(lambda res: res is not None and test_validity(res.oracleStatus))

                found = True

                # data analyse and insert in rigth order
                values = re.findall("..", blockByteRes.block_search_byte)
                found_values_block.insert(0, values[size_block - (i + 1)])

                if (i == 15):
                    result[block - 1] = f'{blockByteRes.ct_pos:02x}' + result[block - 1][3:]
                else:
                    result[block - 1] = result[block - 1][:len_block - i * 2 - 1] + f'{blockByteRes.ct_pos:02x}' + result[block - 1][len_block - i * 2 + 1:]

        result[block-1] = hex_xor(result[block-1], desired_text_bytes_split[block-1])
        found_values_block = []
        print("".join(result))















if __name__ == '__main__':
    retrievePlainText = False
    retrieveQuote = True
    cipher = getCipher().upper()
    if(retrievePlainText):
        plaintext = getPlainText()
    else:
        plaintext = 'You never figure out that "I should have used authenticated encryption because ...". :)'

    secret = plaintext[27:82]

    if(retrieveQuote):
        suffix = ' plain CBC is not secure!'
        cipherText = buildCipherText(secret, suffix)

    print(secret)

"""
authtoken=50b02344eee3237fde748ea1cea3f4a2c83eddf3c318aeaae17bff72895ee5a2ec10a9d30be2074af466b5c3b7d300d6d37cecc3049d8ed492f43aedbb4e8bea36dd82636bdd16f142c4b15f9c883f7534ed5291f477b3b9b61430904412c26f41414141414141414141414141414141; Path=/;
"""