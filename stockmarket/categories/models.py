from django.db import models

# Create your models here.
class Categories(models.Model):
  id = models.IntegerField()
  name = models.CharField(max_length=200)
  description = models.TextField()
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)