import binascii
import hashlib

"""
Credit goes to: https://github.com/bdauvergne/python-pkcs1
"""

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

def string_xor(a, b):
    return bytes(x ^ y for (x, y) in zip(a, b))

def _and_byte(a, b):
    return bytes([a & b])

def _byte_eq(a, b):
    return bytes([a]) == b

def mgf256(mgf_seed, mask_len):
    '''
       Mask Generation Function v1 from the PKCS#1 v2.0 standard.

       mgs_seed - the seed, a byte string
       mask_len - the length of the mask to generate
       hash_class - the digest algorithm to use, default is SHA1

       Return value: a pseudo-random mask, as a byte string
       '''
    hash_class = hashlib.sha256
    h_len = hash_class().digest_size
    if mask_len > 0x10000:
        raise ValueError('mask too long')
    T = b''
    for i in range(0, integer_ceil(mask_len, h_len)):
        C = i2osp(i, 4)
        T = T + hash_class(mgf_seed + C).digest()
    return T[:mask_len]
