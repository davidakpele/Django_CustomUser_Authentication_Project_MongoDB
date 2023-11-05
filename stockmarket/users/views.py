
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from .JwtAuthentication import create_access_token, create_refresh_token, decode_access_token, decode_refresh_token
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import get_authorization_header
from django.http import HttpResponse, HttpResponse, JsonResponse
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth.decorators import login_required
from rest_framework.permissions import IsAuthenticated 
from django.views.decorators.csrf import csrf_exempt
from rest_framework_jwt.settings import api_settings
from django.views.decorators.csrf import csrf_exempt
from rest_framework.exceptions import APIException, AuthenticationFailed
from django.contrib.auth import get_user_model
from django.contrib.auth import login, logout
from django.shortcuts import render, redirect
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import UserSerializer
from .backend import CustomBackend
from rest_framework.authentication import TokenAuthentication
from .models import CustomUsers
from bson import ObjectId
import requests, json

# Create your views here

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

User = get_user_model()
authentication_classes = ()
permission_classes = ()

class UserAPIView(APIView):
    def get(self, request):
        try:

            auth = get_authorization_header(request).split()
            print(auth)
            if auth and len(auth) == 2:
                token = auth[1].decode('utf-8')
                print(token)
                id = decode_access_token(token)

                user = CustomBackend.objects.filter(pk=id).first()

                return Response(UserSerializer(user).data)
            raise AuthenticationFailed('authenticated')
        except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON data', 'status': 400})
        
class RefreshAPIView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get('jwt')
        cleaned_value = refresh_token.lstrip('b').strip("'")
        id = decode_refresh_token(cleaned_value)
        name = request.session['firstname']
        access_token = create_access_token(id, name)
        return Response({
            'token':access_token
        })
        

@login_required(login_url='login')
def index(request):
    return render(request, 'index.html')

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
            user =  CustomUsers.objects.filter(email=email).first()
            if user is not None:
                # Email already exists, send a response with a message
                return JsonResponse({'error': 'User already taken this email address.*', 'status':409}, status=409)
            else:
                firstname = data.get('firstname')
                lastname = data.get('lastname')
                password = data.get('password')
                confirmpassword = data.get('confirmpassword')

                if password == confirmpassword:
                    user = CustomUsers.objects.create_user(email=email, firstname=firstname, lastname=lastname, password=password)
                    user.save()
                    return JsonResponse({'message': 'Account Successfully Created.!', 'status':200})
                else:
                    return JsonResponse({'error': 'Both password are not the same.*', 'status':406}, status=406)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
            
    return HttpResponse({'error': 'Invalid request method', 'status': 405}) 

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

                response.data = {
                    'message': 'Login Successful..!',
                    'token': access_token,
                    'status':200
                }
                response.set_cookie(key='jwt', value=refresh_token, httponly=True)
                return response
            else:
                return JsonResponse({'error': 'Invalid email or password.', 'status': 406}, status=406)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data', 'status': 400})


@login_required(login_url='login')
def logout_view(request):
    logout(request)  # Log the user out and destroy their session
    return redirect('login')  # Redirect to the login page or any other page
