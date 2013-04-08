from django.db import models
from django.utils import timezone

import datetime, uuid

class Request(models.Model):
    ACCOUNT = 'AC'
    TYPE_CHOICES = (
        (ACCOUNT, 'Compte'),
    )
    type = models.CharField(max_length=2, choices=TYPE_CHOICES)
    token = models.CharField(max_length=32)
    uid = models.CharField(max_length=200)
    email = models.EmailField(max_length=254)
    name = models.CharField(max_length=200)
    org_uid = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    expires_at = models.DateTimeField()

    def save(self):
        if not self.expires_at:
            self.expires_at = timezone.now() + datetime.timedelta(days=2)
        if not self.token:
            self.token = str(uuid.uuid4()).translate(None, '-') # remove hyphens
        super(Request, self).save()
