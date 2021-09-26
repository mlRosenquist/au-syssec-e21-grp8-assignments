import json
import random
from types import SimpleNamespace

import requests

url = 'http://127.0.0.1:5000'

class sign_document_response:
    msg : str
    signature: str

class public_key:
    N : int
    e: int

def signRandomDocument(hexstring) -> sign_document_response:
    """
    Call endpoint defined in url
    :return: cipher from endpoint in a hex string
    """
    session = requests.session()
    response = session.get(url+"/sign_random_document_for_students/"+hexstring)
    return json.loads(response.text, object_hook=lambda d: SimpleNamespace(**d))

def getPK() -> public_key:
    """
    Call endpoint defined in url
    :return: cipher from endpoint in a hex string
    """
    session = requests.session()
    response = session.get(url+"/pk/")
    cookies = session.cookies.get_dict()
    return json.loads(response.text, object_hook=lambda d: SimpleNamespace(**d))

def getQuote(msg, signature):
    j = json.dumps({'msg': msg, 'signature': signature})
    session = requests.session()
    session.cookies.set('grade', j)
    r = session.get(url + '/quote')
    return r
if __name__ == '__main__':
    pk = getPK()
    desired_txt = 'You got a 12 because you are an excellent student! :)'
    desired_txt_hex = desired_txt.encode('utf-8').hex()
    desired_txt_bytes = bytes.fromhex(desired_txt_hex)
    desired_txt_int = int.from_bytes(desired_txt_bytes, byteorder='big')


    m1 = 5
    m1_sign = signRandomDocument(f'{m1:02x}')

    s1 = int(m1_sign.signature, 16)
    m1 = int.from_bytes(bytes.fromhex(m1_sign.msg), byteorder='big')

    tmp = desired_txt_int // 5
    m2 = tmp % pk.N

    m2_sign = signRandomDocument(f'{m2:02x}')
    s2 = int(m2_sign.signature, 16)
    m2 = int.from_bytes(bytes.fromhex(m2_sign.msg), byteorder='big')

    s = s1 * s2 % pk.N

    quote = getQuote(desired_txt_hex, s)
    print((m1, s1), (m2, s2))
    #signRandomDocument(f'{m_1:02x}')








