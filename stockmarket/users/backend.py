from django.contrib.auth.backends import ModelBackend
from .models import CustomUsers

class CustomBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        # Your custom authentication logic goes here
        try:
            user = CustomUsers.objects.get(email=email)
            if user.check_password(password):
                return user
        except CustomUsers.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return CustomUsers.objects.get(pk=user_id)
        except CustomUsers.DoesNotExist:
            return None
