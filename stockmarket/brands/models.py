from django.db import models
from categories.models import Categories

# Create your models here.
class Brands(models.Model):
  id = models.IntegerField()
  name = models.CharField(max_length=200)
  cat_id = models.ForeignKey(Categories, on_delete=models.CASCADE)
  description = models.TextField()
  created_at = models.DateTimeField(auto_now_add=True)
  updated_at = models.DateTimeField(auto_now=True)