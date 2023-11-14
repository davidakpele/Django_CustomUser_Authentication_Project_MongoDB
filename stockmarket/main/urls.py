from django.urls import path, include
from . import views
# setting url
urlpatterns = [
    path('', views.index, name='index'),
]