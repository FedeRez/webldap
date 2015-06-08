# Docker-specific local settings

import os

DEBUG = True
TEMPLATE_DEBUG = DEBUG

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'db',
    }
}

# Make this unique, and don't share it with anybody.
SECRET_KEY = ''

TEMPLATE_DIRS = (
    '/srv/webldap/templates',
)

EMAIL_FROM = 'root@localhost'

REQ_EXPIRE_HRS = 48
REQ_EXPIRE_STR = '48 heures'

LDAP_URI = 'ldap://{}:{}'.format(os.environ['LDAP_PORT_389_TCP_ADDR'],
                                 os.environ['LDAP_PORT_389_TCP_PORT'])

LDAP_STARTTLS = False
LDAP_CACERT = ''
LDAP_BASE = 'dc=example,dc=net'
LDAP_WEBLDAP_USER = 'cn=webldap,ou=service-users,dc=example,dc=net'
LDAP_WEBLDAP_PASSWD = 'secret'
LDAP_DEFAULT_GROUPS = []
LDAP_DEFAULT_ROLES = ['member']
