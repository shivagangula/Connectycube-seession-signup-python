import time
import hmac
import requests
import json
import random




app_id = ''
auth_key = ""
auth_secret = ""
API_HOST = "https://api.connectycube.com/session"
user_url = 'https://api.connectycube.com/users'

def hash_hmac_sha1(str_input, secure_secret):
        byte_secure = bytearray(secure_secret, 'utf-8')
        byte_input = bytearray(str_input, 'utf-8')
        signature = hmac.new(byte_secure, byte_input, 'sha1').hexdigest()
        return signature

def generate_signature(user_login, user_pwd):
        nonce = str(random.randint(1, 10000))
        timestamp = str(int(time.time()))
        signature_params = 'application_id={}&auth_key={}&nonce={}&timestamp={}'.format(
            app_id, auth_key, nonce, timestamp
        )
        if user_login is None or user_pwd is None:
            signature_string = '{}'.format(signature_params)
        else:
            signature_user = 'user[login]={}&user[password]={}'.format(user_login, user_pwd)
            signature_string = '{}&{}'.format(signature_params, signature_user)

        signature = hash_hmac_sha1(signature_string, auth_secret)
        return timestamp, nonce, signature

def post_create_session():
        url = "{}".format(API_HOST)
        gen = generate_signature(None, None)
        parameters = {
            'application_id': '{}'.format(app_id),
            'auth_key': auth_key,
            'nonce': gen[1],
            'timestamp': gen[0],
            'signature': gen[2]
        }    
        response = requests.post(url=API_HOST, data=parameters)
        response = response.json()
        token =  response['session']['token'] 
       
        header = {"CB-Token": token, 'Content-Type':  'application/json'}
        sdata = {'user': {'login': 'ganes', 'password': 'pestU4or!'}}
        response = requests.post(user_url, data=json.dumps( sdata), headers= header, allow_redirects=False)
        print( response.text )

post_create_session() 
