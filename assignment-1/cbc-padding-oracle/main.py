import requests
from requests import Session

url = 'http://localhost:5000'

def getAuthToken():
    # Get cookie
    session = requests.session()
    session.get(url)
    cookies = session.cookies.get_dict()
    return cookies['authtoken']

def getQuote(authToken):
    # Get cookie
    cookies = {'authtoken': authToken}
    r = requests.get(url+'/quote', cookies=cookies)

    return r.text

def manipulateAuthToken(initialToken, newByte, newByteIndex):
    stringBytes = str.encode(initialToken)
    print(stringBytes.hex())
    stringBytes = stringBytes[0:newByteIndex] + newByte + stringBytes[newByteIndex+1:]
    print(stringBytes.hex())
    return stringBytes.decode()


authToken = getAuthToken()
print(authToken)

newToken = manipulateAuthToken(authToken, b'\x24', 127)
newToken = manipulateAuthToken(authToken, b'\x25', 126)
newToken = manipulateAuthToken(authToken, b'\x26', 125)
newToken = manipulateAuthToken(authToken, b'\x27', 124)
print(newToken)

quote = getQuote(authToken)

print(quote)
