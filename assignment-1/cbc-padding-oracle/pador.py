from Crypto.Cipher import AES
import sys
key = b"aaaabbbbccccdddd"
iv = b"1111222233334444"

def decr(ciphertext):
  cipher = AES.new(key, AES.MODE_CBC, iv)
  return ispkcs7(cipher.decrypt(ciphertext))

def ispkcs7(plaintext):
  l = len(plaintext)
#   c = ord(int(plaintext[l-1]))           
#   c = int.from_bytes(plaintext[l-1], sys.byteorder) 
  c = plaintext[l-1]           
  if (c > 16) or (c < 1):
    return "PADDING ERROR"
  if int.from_bytes(plaintext[l-c:], sys.byteorder) != c*c:
    # print(plaintext[l-c:])
    return "PADDING ERROR"
  return plaintext

def encr(plaintext):
  cipher = AES.new(key, AES.MODE_CBC, iv)
  ciphertext = cipher.encrypt(pkcs7(plaintext))
  return ciphertext

def pkcs7(plaintext):
  padbytes = 16 - len(plaintext) % 16
  pad = padbytes * chr(padbytes).encode()
  return plaintext + pad 