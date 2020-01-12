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


def lambda_handler(event, context):
    # TODO implement
    for field in ["username","email","password","name"]:
        if not  event.get(field):
            return {
                "error":False,"success":True,
                "message":f"{field} is not present . ","data":None            
                
            }
    username=event["username"]
    name=event["name"]
    email=event["email"]
    password=event["password"]
    
    client=boto3.client('cognito-idp')
    
    try:
        resp=client.sign_up(
            ClientId=USER_CLIENT_ID,
            SecretHash=get_secret_hash(username),
            Username=username,
            Password=password, 
            UserAttributes=[
            {
                'Name': "name",
                'Value': name
            },
            {
                'Name': "email",
                'Value': email
            }
            ],
            ValidationData=[
                {
                'Name': "email",
                'Value': email
            },
            {
                'Name': "custom:username",
                'Value': username
            }
            ]
            )
            #exception handling when username is repeated 
    except client.exceptions.UsernameExistsException as e:
        return {"error": False, 
               "success": True, 
               "message": "This username already exists", 
               "data": None}
               
            #wrong type of passwords   
    except client.exceptions.InvalidPasswordException as e:
        
        return {"error": False, 
               "success": True, 
               "message": "Password should have Caps, Special chars, Numbers", 
               "data": None}
               
               
               
    except client.exceptions.UserLambdaValidationException as e:
        return {"error": False, 
               "success": True, 
               "message": "Email already exists", 
               "data": None}
    
    except Exception as e:
        return {"error": False, 
                "success": True, 
                "message": str(e), 
               "data": None}
    
    return {"error": False, 
            "success": True, 
            "message": "Please confirm your signup, check Email for validation code", 
            "data": None}
    
    
    
    
    return {
        "code":200,
        "message":"Not working properly . "
    }
