from django.db import models
from django.utils import timezone

import datetime

class AccountRequest(models.Model):
    token = models.CharField(max_length=32)
    uid = models.CharField(max_length=200)
    email = models.EmailField(max_length=254)
    name = models.CharField(max_length=200)
    org_uid = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    expires_at = models.DateTimeField(editable=False)

    def save(self):
        self.expires_at = timezone.now() + datetime.timedelta(days=2)
        super(AccountRequest, self).save()
