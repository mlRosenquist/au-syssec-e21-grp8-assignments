import requests
from requests import Session

url = 'https://cbc.syssec.lnrd.net/'

def getAuthToken() -> str:
    # Get cookie
    session = requests.session()
    session.get(url)
    cookies = session.cookies.get_dict()
    # return cookies['authtoken']
    return '0c4746d2e40f6e2ee0a2818d8e2ef235ad41362341e19134c38e4d0150a31804b6b13c50586c408c9610afaa8cfac6ffc463ce17141b56bae954b76d576aded9a40389bab83cbdf31fc46227797b2fe0e8b64a03ccf313ebee17acf0bf8e36ee9dafd615c3d4df4e13fe959387c79905'

def getQuote(authToken):
    # Get cookie
    cookies = {'authtoken': authToken}
    # print(authToken)
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
