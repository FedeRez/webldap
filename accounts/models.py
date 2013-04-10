from django.db import models
from django.utils import timezone
from federez_ldap import settings

import datetime, uuid

class Request(models.Model):
    ACCOUNT = 'AC'
    PASSWD = 'PW'
    EMAIL = 'EM'
    TYPE_CHOICES = (
        (ACCOUNT, 'Compte'),
        (PASSWD, 'Mot de passe'),
        (EMAIL, 'Email'),
    )
    type = models.CharField(max_length=2, choices=TYPE_CHOICES)
    token = models.CharField(max_length=32)
    uid = models.CharField(max_length=200)
    email = models.EmailField(max_length=254)
    name = models.CharField(max_length=200, verbose_name='nom')
    org_uid = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    expires_at = models.DateTimeField()

    def save(self):
        if not self.expires_at:
            self.expires_at = timezone.now() \
                            + datetime.timedelta(hours=settings.REQ_EXPIRE_HRS)
        if not self.token:
            self.token = str(uuid.uuid4()).translate(None, '-') # remove hyphens
        super(Request, self).save()
