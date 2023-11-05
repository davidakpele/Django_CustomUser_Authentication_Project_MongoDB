# models.py
from django.http import HttpResponse
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models

# Create your model here

User = get_user_model()

class CustomUserManager(BaseUserManager):
    def create_user(self, email, firstname, lastname, password=None):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, firstname=firstname, lastname=lastname)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
def create_superuser(self, email, firstname, lastname, password=None):
        user = self.create_user(email, firstname, lastname, password)
        user.is_admin = True
        user.save(using=self._db)
        return user


class CustomUsers(AbstractBaseUser):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    firstname = models.CharField(max_length=100, blank=True) 
    lastname = models.CharField(max_length=100, blank=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=100, blank=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    def __str__(self):
        return self.firstname
    
    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return self.is_admin
    
    
class Trader(models.Model):
    id_user = models.IntegerField()
    name = models.CharField(max_length=100, blank=True) 
    initial_balance = models.DecimalField(max_digits=10, decimal_places=2, default=100.00)
    current_balance = models.DecimalField(max_digits=10, decimal_places=2, default=100.00)

class Transaction(models.Model):
    trader = models.ForeignKey(Trader, on_delete=models.CASCADE)
    amount = models.FloatField()
    timestamp = models.DateTimeField()

   

    