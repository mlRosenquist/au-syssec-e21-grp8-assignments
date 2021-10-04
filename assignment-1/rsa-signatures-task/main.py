import binascii
import json
import math
import secrets
import hashlib
import sys

import primitives as primitives
from flask import Flask, request, make_response, redirect, url_for
from secret_data import rsa_key

app = Flask(__name__)
quotes = open('quotes.txt', 'r').readlines()

"""
Inspired by: https://github.com/bdauvergne/python-pkcs1
Recipe from: https://datatracker.ietf.org/doc/html/rfc8017
"""

def emsa_pss_encode(message: bytes, emBits: int) -> bytes:

    # 1
    if len(message) > ((2**64)-1):
        raise ValueError('message too long')

    # 2
    sha_256 = hashlib.sha256()
    sha_256.update(message)
    mHash = sha_256.digest()
    hLen = len(mHash)
    sLen = 32
    emLen = primitives.integer_ceil(emBits, 8)

    # 3
    if emLen < (sLen + hLen + 2):
        raise ValueError('encoding error')

    # 4
    salt = secrets.token_bytes(sLen)

    # 5
    M = bytes(b'\x00' * 8) + mHash + salt

    # 6
    sha_256 = hashlib.sha256()
    sha_256.update(M)
    H = sha_256.digest()

    # 7
    PS = bytes(b'\x00' * (emLen - sLen - hLen - 2))

    # 8
    DB = PS + b'\x01' + salt

    # 9
    dbMask = primitives.mgf256(H, emLen - hLen - 1)

    # 10
    dbMask = primitives.string_xor(DB, dbMask)

    # 11
    octets, bits = (8 * emLen - emBits) // 8, (8 * emLen - emBits) % 8
    dbMask = (b'\x00' * octets) + dbMask[octets:]
    new_byte = bytes([dbMask[octets] & 255 >> bits])
    dbMask = dbMask[:octets] + new_byte + dbMask[octets + 1:]

    # 12
    EM = dbMask + H + b'\xbc'

    # 13
    return EM


def rsassa_pss_sign(message: bytes) -> bytes:
    # modulus and private exponent
    N = rsa_key['_n']
    d = rsa_key['_d']
    modBits = 3072

    # 1
    EM = emsa_pss_encode(message, (modBits - 1))

    # 2
    m = primitives.os2ip(EM)
    s = primitives.rsasp1((d, N), m)
    S = primitives.i2osp(s, 128*3)

    # 3
    return S


def emsa_pss_verify(message: bytes, em: bytes, emBits: int) -> bool:
    # 1
    if len(message) > ((2**64)-1):
        return False

    # 2
    sha_256 = hashlib.sha256()
    sha_256.update(message)
    mHash = sha_256.digest()
    hLen = len(mHash)
    sLen = 32
    em_len = primitives.integer_ceil(emBits, 8)

    # 3
    if em_len < (sLen + hLen + 2):
        return False

    # 4
    if not primitives._byte_eq(em[-1], b'\xbc'):
        return False

    # 5
    maskedDB, h = em[:em_len-hLen-1], em[em_len-hLen-1:-1]

    # 6.
    octets, bits = (8 * em_len - emBits) // 8, (8 * em_len - emBits) % 8
    zero = maskedDB[:octets] + primitives._and_byte(maskedDB[octets], ~(255 >> bits))
    for c in zero:
        if not primitives._byte_eq(c, b'\x00'):
            return False

    # 7.
    db_mask = primitives.mgf256(h, em_len - hLen - 1)

    # 8.
    db = primitives.string_xor(maskedDB, db_mask)

    # 9.
    new_byte = primitives._and_byte(db[octets], 255 >> bits)
    db = (b'\x00' * octets) + new_byte + db[octets + 1:]

    # 10.
    for c in db[:em_len - hLen - sLen - 2]:
        if not primitives._byte_eq(c, b'\x00'):
            return False
    if not primitives._byte_eq(db[em_len - hLen - sLen - 2], b'\x01'):
        return False

    # 11
    salt = db[-sLen:]

    # 12.
    m_prime = (b'\x00' * 8) + mHash + salt

    # 13.
    sha_256 = hashlib.sha256()
    sha_256.update(m_prime)
    h_prime = sha_256.digest()

    # 14.
    result = True
    for x, y in zip(h_prime, h):
        result &= (x == y)
    return result


def rsassa_pss_verify(message: bytes, signature: bytes) -> bool:
    n = rsa_key['_n']
    d = rsa_key['_d']
    e = rsa_key['_e']

    modBits = 3072
    embits = modBits - 1
    emLen = primitives.integer_ceil(embits, 8)
    # 1
    if(len(signature) != 128 * 3):
        return False

    # 2
    s = primitives.os2ip(signature)
    m = primitives.rsavp1((n, e), s)
    EM = primitives.i2osp(m, emLen)

    # 3
    verified = emsa_pss_verify(message, EM, embits)

    # 4
    return verified


def sign(message: bytes) -> bytes:
    """Sign a message using our private key."""
    # modulus and private exponent
    N = rsa_key['_n']
    d = rsa_key['_d']
    # interpret the bytes of the message as an integer stored in big-endian
    # byte order
    m = int.from_bytes(message, 'big')
    if not 0 <= m < N:
        raise ValueError('message too long')
    # compute the signature
    s = pow(m, d, N)
    # encode the signature into a bytes using big-endian byte order
    signature = s.to_bytes(math.ceil(N.bit_length() / 8), 'big')
    return signature


def verify(message: bytes, signature: bytes) -> bool:
    """Verify a signature using our public key."""
    # modulus and private exponent
    N = rsa_key['_n']
    e = rsa_key['_e']
    # interpret the bytes of the message and the signature as integers stored
    # in big-endian byte order
    m = int.from_bytes(message, 'big')
    s = int.from_bytes(signature, 'big')
    if not 0 <= m < N or not 0 <= s < N:
        raise ValueError('message or signature too large')
    # verify the signature
    mm = pow(s, e, N)
    return m == mm



@app.route('/')
def index():
    """Redirect to the grade page."""
    return redirect(url_for('grade'))


@app.route('/pk/')
def pk():
    """Publish our public key as JSON."""
    N = int(rsa_key['_n'])
    e = int(rsa_key['_e'])
    return {'N': N, 'e': e}


@app.route('/grade/')
def grade():
    """Grade student's work and store the grade in a cookie."""
    if 'grade' in request.cookies:  # there is a grade cookie, try to load and verify it
        try:
            # deserialize the JSON object which we expect in the cookie
            j = json.loads(request.cookies.get('grade'))
            # decode the hexadecimal encoded byte strings
            msg = bytes.fromhex(j['msg'])
            signature = bytes.fromhex(j['signature'])
            # check if the signature is valid
            if not rsassa_pss_verify(msg, signature):
                return '<p>Hm, are you trying to cheat?.</p>'
            return f'<p>{msg.decode()}</p>'
        except Exception as e:
            # if something goes wrong, delete the cookie and try again
            response = redirect(url_for('grade'))
            response.delete_cookie('grade')
            return response
    else:  # the student has not yet been graded, lets do this
        # think very hard, which grade the student deserves
        g = secrets.choice(['-3', '00', '02', '4', '7', '10']) # nobody gets a 12 in my course
        # create the message and UTF-8 encode it into bytes
        msg = f'You get a only get a {g} in System Security. I am very disappointed by you.'.encode()
        # sign the message
        signature = rsassa_pss_sign(msg)
        # serialize message and signature into a JSON object; for the byte
        # strings we use hexadecimal encoding
        j = json.dumps({'msg': msg.hex(), 'signature': signature.hex()})
        # create a response object
        response = make_response('<p>Here is your grade, and take a cookie!</p>')
        # and store the created JSON object into a cookie
        response.set_cookie('grade', j)
        return response



@app.route('/quote/')
def quote():
    """Show a quote to good students."""
    try:
        # deserialize the JSON object which we expect in the cookie
        j = json.loads(request.cookies.get('grade'))
        # decode the hexadecimal encoded byte strings
        msg = bytes.fromhex(j['msg'])
        signature = bytes.fromhex(j['signature'])
    except Exception as e:
        print(e)
        return '<p>Grading is not yet done, come back next year.</p>'
    # check if the signature is valid
    if not rsassa_pss_verify(msg, signature):
        return '<p>Hm, are you trying to cheat?.</p>'
    # check if the student is good
    if msg == b'You got a 12 because you are an excellent student! :)':
        return f'<quote>\n{secrets.choice(quotes)}</quote>'
    else:
        print(msg)
        return '<p>You should have studied more!</p>'


# students always want me to sign their stuff, better automate this
@app.route('/sign_random_document_for_students/<data>/')
def sign_random_document_for_student(data):
    """Sign a given message as long as it does not contain a grade.

    The data is expected in hexadecimal encoding as part of the URL.  E.g.,
    `/sign_random_document_for_students/42424242/` returns a signature of the
    string 'BBBB'.
    """
    # hex-decode the data
    msg = bytes.fromhex(data)
    # check if there are any forbidden words in the message
    if any(x.encode() in msg for x in ['grade', '12', 'twelve', 'tolv']):
        return '<p>Haha, nope!</p>'
    try:  # try to sign the message
        signature = rsassa_pss_sign(msg)
        # return message and signature hexadecimal encoded in a JSON object
        return {'msg': msg.hex(), 'signature': signature.hex()}
    except Exception as e:  # something went wrong
        return {'error': str(e)}

msg = f'hello'.encode()
# sign the message
signature = rsassa_pss_sign(msg)
verified = rsassa_pss_verify(msg, signature)

print(verified)