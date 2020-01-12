import json
import boto3
import botocore.exceptions
import hmac
import hashlib
import base64

USER_POOL_ID='' 
USER_CLIENT_ID=''
CLIENT_SECRET=''


def get_secret_hash(username):
    msg=username+USER_CLIENT_ID
    #particular message which is unique for every user 
    dig=hmac.new(str(CLIENT_SECRET).encode('utf-8'))
    #used by base 64
    msg=str(msg).encode('utf-8')
    #encode our message
    hash_code=hashlib.sha256(msg).hexdigest()
    #hash_code is the hash code which then use by base 64 module
    d2=base64.b64decode(dig).encode()
    return d2



def initiate_auth(client, username, password):
  secret_hash = get_secret_hash(username)
    try:
      resp = client.admin_initiate_auth(
                 UserPoolId=USER_POOL_ID,
                 ClientId=CLIENT_ID,
                 AuthFlow='ADMIN_NO_SRP_AUTH',
                 AuthParameters={
                     'USERNAME': username,
                     'SECRET_HASH': secret_hash,
                     'PASSWORD': password,
                  },
                ClientMetadata={
                  'username': username,
                  'password': password,              })    except client.exceptions.NotAuthorizedException:
        return None, "The username or password is incorrect"
    except client.exceptions.UserNotConfirmedException:
        return None, "User is not confirmed"
    except Exception as e:
        return None, e.__str__()
  return resp, None

def lambda_handler(event, context):
    # TODO implement
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
