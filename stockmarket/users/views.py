from django.views import View
from .JwtAuthentication import create_access_token, create_refresh_token, decode_access_token, decode_refresh_token
from django.http import HttpResponse, HttpResponse, HttpResponseNotFound, JsonResponse
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.exceptions import APIException, AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import get_authorization_header
from django.contrib.auth.decorators import login_required
from rest_framework.renderers import JSONRenderer
from rest_framework.permissions import IsAuthenticated
from django.views.decorators.csrf import csrf_exempt
from rest_framework_jwt.settings import api_settings
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from django.contrib.auth import get_user_model
from django.contrib.auth import login, logout
from django.shortcuts import render, redirect
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import UserSerializer
from rest_framework import exceptions
from .backend import CustomBackend
from .models import CustomUsers
from datetime import datetime
import requests
import json
import jwt
import os


jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

User = get_user_model()
authentication_classes = ()
permission_classes = ()


class RecreateRefreshTokenAPIView(APIView):
    def post(self, request):
        # Extract the refresh token from the request data
        token = request.data.get('jwt')
        user_name = request.data.get('username')
        role = request.data.get('role')
        if not token:
            raise exceptions.AuthenticationFailed({
                "status": 401,
                "title": "Authentication Error",
                "detail": "Refresh token is required for recreation.",
                "code": "missing_refresh_token"
            })
        try:
            user_id = decode_refresh_token(token)
            # Create new access and refresh tokens
            new_access_token = create_access_token(user_id, user_name)
            new_refresh_token = create_refresh_token(user_id, user_name)

            # Create the response with the new tokens
            response_data = {
                'jwt': new_refresh_token,
                'cursor': '',
                'api': {
                    'aot': {
                        'imprint': 'micro-lock-down',
                        'syphine': [
                            '64-bit-encryption',
                        ],
                        'user':{
                            'username': user_name,
                            'role': role,
                        },
                        'access_token': [
                            new_access_token,  # Include the old refresh token for reference
                        ],
                    },
                },
                'asyc': len('http.headers'),
                'post_add': os.getpid(),
                'status': 200
            }

            response = Response(data=response_data)
            response.set_cookie(
                key='jwt', value=new_refresh_token, httponly=True)

            return response

        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed({
                "status": 401,
                "title": "Authentication Error",
                "detail": "Refresh token has expired.",
                "code": "expired_refresh_token"
            })
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed({
                "status": 401,
                "title": "Authentication Error",
                "detail": "Invalid refresh token.",
                "code": "invalid_refresh_token"
            })

class LoginView(APIView):
    def post(self, request):
        try:
            email = request.data.get('email')
            password = request.data.get('password')
            # Check if the email and password are provided in the JSON data
            if email is None or password is None:
                return JsonResponse({'error': 'Email and password are required'}, status=409)

            # Authenticate the user
            UserAuth = CustomBackend()
            user = UserAuth.authenticate(request, email=email, password=password)
            if user is not None:

                request.session['firstname'] = user.firstname
                request.session['lastname'] = user.lastname
                request.session['email'] = user.email
                login(request, user)
                    
                access_token = create_access_token(user.id, user.firstname)
                refresh_token = create_refresh_token(user.id, user.firstname)

                response = Response()
                role =''
                if user.is_admin:
                    role='admin'
                elif user.is_admin is not True:
                    role='visitor'
                response.data = {
                    'message': 'Login Successful..!',
                    'token': refresh_token,
                    'username': user.firstname,
                    'role': role,
                    'status':200
                }
                response.set_cookie(key='jwt', value=refresh_token, httponly=True)
                return response
            else:
                return JsonResponse({'error': 'Invalid email or password.', 'status': 406}, status=406)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data', 'status': 400})


@login_required(login_url='login')
def index(request):
    return render(request, 'index.html')


def check_authorization_bearer(request):
    authorization_header = request.META.get('HTTP_AUTHORIZATION')
    if authorization_header:
        auth_parts = authorization_header.split()
        if len(auth_parts) == 2 and auth_parts[0].lower() == 'bearer':
            token = auth_parts[1]
            id = decode_access_token(token)
            if id is False:
                return JsonResponse({"detail": "Given token not valid for any token type", "code": "token_not_valid", "messages": [{"token_class": "AccessToken",  "token_type": "access", "message": "Token is invalid or expired"}]})
            else:
                # Decode without verification for the sake of getting expiration
                decoded_token = jwt.decode(token, verify=False)
                expiration_timestamp = decoded_token['exp']

                current_time = datetime.utcnow().timestamp()

                if current_time > expiration_timestamp:
                    return JsonResponse({"detail": "Given token not valid for any token type", "code": "token_not_valid", "messages": [{"token_class": "AccessToken",  "token_type": "access", "message": "Token has expired"}]})
                else:
                    user = CustomUsers.objects.filter(pk=id).first()
                    return JsonResponse(UserSerializer(user).data)

    return HttpResponse(status=401)  # Unauthorized status


def UserAPIView(request):
    result = check_authorization_bearer(request)
    return result


def renderRegister_view(request):
    # Your view logic can go here
    if 'lastname' in request.session and 'firstname' in request.session:
        # Both session variables are set, so redirect to the dashboard
        return redirect('/')
    else:
        # Render the view template or perform other actions as needed
        return render(request, 'auth/register.html')


def renderLogin_view(request):
    if 'lastname' in request.session and 'firstname' in request.session:
        return redirect('/')
    else:
        # Render the view template or perform other actions as needed
        return render(request, 'auth/login.html')


@csrf_exempt
def authenticate_users_registration(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        try:
            user = CustomUsers.objects.filter(email=email).first()
            if user is not None:
                # Email already exists, send a response with a message
                return JsonResponse({'error': 'User already taken this email address.*', 'status': 409}, status=409)
            else:
                firstname = data.get('firstname')
                lastname = data.get('lastname')
                password = data.get('password')
                confirmpassword = data.get('confirmpassword')

                if password == confirmpassword:
                    user = CustomUsers.objects.create_user(
                        email=email, firstname=firstname, lastname=lastname, password=password)
                    user.save()
                    return JsonResponse({'message': 'Account Successfully Created.!', 'status': 200})
                else:
                    return JsonResponse({'error': 'Both password are not the same.*', 'status': 406}, status=406)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)

    return HttpResponse({'error': 'Invalid request method', 'status': 405})


def logout_view(request):
    logout(request)
    response = Response()
    for key in request.COOKIES:
        response.delete_cookie(key)
      # Set the desired HTTP status code in the response
    return JsonResponse({'message': 'Successfully Logout.!', 'status': 200}, status=200)