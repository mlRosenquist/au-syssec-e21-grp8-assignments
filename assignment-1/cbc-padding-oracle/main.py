import requests
from requests import Session

url = 'https://cbc.syssec.lnrd.net/'

def getAuthToken() -> str:
    # Get cookie
    session = requests.session()
    session.get(url)
    cookies = session.cookies.get_dict()
    return cookies['authtoken']

def getQuote(authToken):
    # Get cookie
    cookies = {'authtoken': authToken}
    print(authToken[len(authToken)-36-2:])
    r = requests.get(url+'/quote', cookies=cookies)
    return r.text

def manipulateAuthToken(initialToken, newByte, newByteIndex):
    stringBytes = str.encode(initialToken)
    print(stringBytes.hex())
    stringBytes = stringBytes[0:newByteIndex] + newByte + stringBytes[newByteIndex+1:]
    print(stringBytes.hex())
    return stringBytes.decode()


# authToken = getAuthToken()
# print(authToken)

# newToken = manipulateAuthToken(authToken, b'\x64', 127)
# print(newToken)

# quote = getQuote(newToken)

# print(quote)
