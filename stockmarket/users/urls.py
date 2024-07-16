from django.urls import path, include
from . import views
from .views import LoginView, UserAPIView, RefreshAPIView
# setting url

urlpatterns = [
    path('', views.index, name='index'),
    path('register/', views.renderRegister_view, name='register'),
    path('login/', views.renderLogin_view, name='login'),
    path('auth/register', views.authenticate_users_registration, name='auth/register'),
    path('logout/', views.logout_view, name='logout'),
    path('auth/login', LoginView.as_view(), name='auth/login'), 
    path('api/auth/user', views.UserAPIView, name='api/auth/user'),
    path('api/collect', RefreshAPIView.as_view(), name='collect-data'),
]