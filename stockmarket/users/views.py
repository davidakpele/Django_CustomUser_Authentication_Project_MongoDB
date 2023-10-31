from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from .models import Transaction
from .models import CustomUsers
from django.contrib.auth import get_user_model
from .backend import CustomBackend
import json
import plotly.express as px
from bson import ObjectId  # Import the ObjectId class from PyMongo


User = get_user_model()
# Create your views here.

@login_required(login_url='login')
def index(request):
     # Retrieve transaction data for the logged-in user
    user_transactions = Transaction.objects.filter(trader__user=request.user)
     # Prepare data for the Plotly graph
    profit_loss_data = {
        'x': [str(transaction.timestamp) for transaction in user_transactions],
        'y': [transaction.amount for transaction in user_transactions],
    }
    return render(request, 'index.html',  {'profit_loss_data': profit_loss_data})


def renderRegister_view(request):
    # Your view logic can go here
    if 'lastname' in request.session and 'firstname' in request.session:
        # Both session variables are set, so redirect to the dashboard
        return redirect('/')
    else:
        # Render the view template or perform other actions as needed
        return render(request, 'auth/register.html')
    
def renderLogin_view(request):
    # Your view logic can go here
    if 'lastname' in request.session and 'firstname' in request.session:
        # Both session variables are set, so redirect to the dashboard
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


@csrf_exempt
def authenticate_users_login(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')

            # Check if the email and password are provided in the JSON data
            if email is None or password is None:
                return JsonResponse({'error': 'Email and password are required'},  status=409)
            # Authenticate the user
            UserAuth= CustomBackend()
            user = UserAuth.authenticate(request, email=email, password=password)
            if user is not None:
                # Create an ObjectId
                object_id = ObjectId()
                # Convert the ObjectId to a string
                object_id_str = str(object_id)
                # Serialize the string to JSON
                json_data = json.dumps({"_id": object_id_str, "email":email})
                request.session['user_id'] = json_data
                request.session['firstname']=user.firstname
                request.session['lastname']=user.lastname
                request.session['email']=user.email
                login(request, user)
                return JsonResponse({'message': 'Login Successful..!', 'status': 200})
            else:
                return JsonResponse({'error': 'Invalid email or password.', 'status': 406}, status=406)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data', 'status': 400})

    return JsonResponse({'error': 'Invalid request method', 'status': 405})


def logout_view(request):
    logout(request)  # Log the user out and destroy their session
    return redirect('login')  # Redirect to the login page or any other page
