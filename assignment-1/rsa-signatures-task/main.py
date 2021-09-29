import binascii
import json
import math
import secrets
import hashlib
from flask import Flask, request, make_response, redirect, url_for
from secret_data import rsa_key

app = Flask(__name__)
quotes = open('quotes.txt', 'r').readlines()


def i2osp(x, x_len):
    '''Converts the integer x to its big-endian representation of length
       x_len.
    '''
    if x > 256**x_len:
        raise ValueError('message too long')
    h = hex(x)[2:]
    if h[-1] == 'L':
        h = h[:-1]
    if len(h) & 1 == 1:
        h = '0%s' % h
    x = binascii.unhexlify(h)
    return b'\x00' * int(x_len-len(x)) + x

def os2ip(x):
    '''Converts the byte string x representing an integer reprented using the
       big-endian convient to an integer.
    '''
    h = binascii.hexlify(x)
    return int(h, 16)


def rsasp1(key: tuple, message: int) -> int:
    d = key[0]
    n = key[1]
    if not 0 <= message < n:
        raise ValueError('message representative out of range')
    s = pow(message, d, n)
    return s

def integer_ceil(a, b):
    '''Return the ceil integer of a div b.'''
    quanta, mod = divmod(a, b)
    if mod:
        quanta += 1
    return quanta

def rsavp1(key: tuple, signature: int) -> int:
    n = key[0]
    e = key[1]
    if not 0 <= signature < n:
        raise ValueError('message representative out of range')
    m = pow(signature, e, n)
    return m


def emsa_pss_encode(message: bytes, emBits: int) -> bytes:
    if len(message) > ((2^64)-1):
        raise ValueError('message too long')
    sha_256 = hashlib.sha256()
    sha_256.update(message)
    mHash = sha_256.digest()
    hLen = len(mHash)
    sLen = 32

    emLen = integer_ceil(emBits, 8)

    if emLen < (sLen + hLen + 2):
        raise ValueError('encoding error')
    salt = secrets.token_bytes(sLen)
    M = bytearray(b'\x00' * 8) + mHash + salt
    sha_256 = hashlib.sha256()
    sha_256.update(M)
    H = sha_256.digest()
    PS = bytearray(b'\x00' * (emLen - sLen - hLen - 2))
    DB = PS + b'\x01' + salt
    sha_256 = hashlib.sha256()
    sha_256.update(H)
    dbMask = sha_256.digest()
    maskedDB = DB ^ dbMask
    maskedDB[:(8 * emLen)-emBits] = 0
    EM = maskedDB + H + b'\xbc'
    return EM

def emsa_pss_verify(message: bytes, em: bytes, emBits: int) -> bool:
    if len(message) > ((2^64)-1):
        return False
    sha_256 = hashlib.sha256()
    sha_256.update(message)
    mHash = sha_256.digest()

    hLen = len(mHash)
    sLen = 32
    emLen = integer_ceil(emBits, 8)

    if emLen < (sLen + hLen + 2):
        raise False

    if not em[-1] == b'\xbc':
        return False

    masked_db, h = em[:emLen-hLen-1], em[emLen-hLen-1:-1]

    octets, bits = (8 * emLen - emBits) // 8, (8 * emLen - emBits) % 8
    zero = masked_db[:octets] + masked_db[octets] & ~(255 >> bits)

    for c in zero:
        if not c == b'\x00':
            return False

    sha_256 = hashlib.sha256()
    sha_256.update(h)
    dbMask = sha_256.digest()

    # 8
    db = masked_db ^ dbMask

    # 9
    new_byte = db[octets] & 255 >> bits
    db = (b'\x00' * octets) + new_byte + db[octets + 1:]

    # 10
    for c in db[:emLen-hLen-sLen-2]:
        if not c == b'\x00':
            return False
    if not db[emLen-hLen-sLen-2] == b'\x01':
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

def rsassa_pss_sign(message: bytes, key: bytes) -> bytes:
    # modulus and private exponent
    N = rsa_key['_n']
    d = rsa_key['_d']

    modBits = 3072
    EM = emsa_pss_encode(message, (modBits - 1))
    m = os2ip(EM)
    s = rsasp1((d, N), m)
    S = i2osp(s, 128)
    return S


def rsassa_pss_verify(message: bytes, signature: bytes) -> bool:
    n = rsa_key['_n']
    d = rsa_key['_d']
    e = rsa_key['_e']

    #k =
    #if(len(s) !=)
    modBits = 3072
    s = os2ip(signature)
    m = rsavp1((n, e), s)
    embits = modBits-1
    em_len = integer_ceil(embits, 8)
    em = i2osp(m, em_len)

    verified = emsa_pss_verify(message, em, embits)
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
            if not verify(msg, signature):
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
        signature = sign(msg)
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
    if not verify(msg, signature):
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
        signature = sign(msg)
        # return message and signature hexadecimal encoded in a JSON object
        return {'msg': msg.hex(), 'signature': signature.hex()}
    except Exception as e:  # something went wrong
        return {'error': str(e)}

msg = f'hello'.encode()
# sign the message
signature = sign(msg)
verified = rsassa_pss_verify(msg, signature)

print(signature)