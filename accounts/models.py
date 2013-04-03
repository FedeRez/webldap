from django.db import models

class AccountRequest(models.Model):
    token = models.CharField(max_length=32)
    uid = models.CharField(max_length=200)
    email = models.EmailField(max_length=254)
    name = models.CharField(max_length=200)
    org_uid = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add = True)
