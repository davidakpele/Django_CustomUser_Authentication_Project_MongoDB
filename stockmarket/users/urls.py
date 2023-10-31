from django.urls import path, include
from . import views
# setting url
urlpatterns = [
    path('', views.index, name='index'),
    path('register/', views.renderRegister_view, name='register'),
    path('login/', views.renderLogin_view, name='login'),
    path('auth/login', views.authenticate_users_login, name='auth/login'),
    path('auth/register', views.authenticate_users_registration, name='auth/register'),
    path('logout/', views.logout_view, name='logout'),
    
]