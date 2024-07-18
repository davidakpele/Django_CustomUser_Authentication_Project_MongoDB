from django.http import JsonResponse
from rest_framework import exceptions
import jwt, datetime, json

def create_access_token(id, name):
    return jwt.encode({
        'user_id': id,
        'name':name,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
        'iat': datetime.datetime.utcnow(),
    }, 'access_secret', algorithm='HS256')

def decode_access_token(token):
    try:
        payload = jwt.decode(token, 'access_secret', algorithms='HS256')    
        return payload['user_id']
    except jwt.InvalidTokenError:  
        # Handle JWT expiration error if needed
        return False

def create_refresh_token(id, name):
    return jwt.encode({
        'user_id': id,
        'name':name,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow(),
    }, 'refresh_secret', algorithm='HS256')

def decode_refresh_token(token):
    try:
        payload = jwt.decode(token, 'refresh_secret', algorithms='HS256')   
        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed({
            "status": 401,
            "title": "Authentication Error",
            "detail": "Something went wrong with authentication to your Skybase library.",
            "code": "generic_authentication_error"
        })