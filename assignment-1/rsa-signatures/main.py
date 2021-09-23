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
    cookies = \
        {
        'msg': msg,
        'signature': signature
        }
    r = requests.get(url + '/quote', cookies=cookies)
    return r
if __name__ == '__main__':
    pk = getPK()
    BBBB_sign = signRandomDocument('42424242')

    random_int = random.randint(1, 10)**pk.e

    message = (BBBB_sign.signature * random_int) % pk.N








