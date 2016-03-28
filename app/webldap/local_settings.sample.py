DEBUG = True
TEMPLATE_DEBUG = DEBUG

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.',  # Add 'postgresql_psycopg2', 'mysql', 'sqlite3'.
        'NAME': '',             # Or path to database file if using sqlite3.
        'USER': '',             # Not used with sqlite3.
        'PASSWORD': '',         # Not used with sqlite3.
        'HOST': '',             # Set to empty string for localhost. Not used with sqlite3.
        'PORT': '',             # Set to empty string for default. Not used with sqlite3.
    }
}

# Make this unique, and don't share it with anybody.
SECRET_KEY = ''

# Absolute paths to template directories
TEMPLATE_DIRS = (
)

# SMTP relay (host and port) to use for confirmation mails
EMAIL_HOST = 'mail.example.net'
EMAIL_PORT = 25

# Email `From` field
EMAIL_FROM = 'support@example.net'

# Number of hours a token remains valid after having been created.  Numeric and string
# versions should have the same meaning.
REQ_EXPIRE_HRS = 48
REQ_EXPIRE_STR = '48 heures'

# LDAP server URI (protocol and address)
LDAP_URI = 'ldap://ldap.example.net'

# Whether to use STARTTLS
LDAP_STARTTLS = False

# Certificate used with LDAPS or STARTTLS
LDAP_CACERT = ''

# LDAP base DN
LDAP_BASE = 'dc=example,dc=net'

# LDAP application DN
LDAP_WEBLDAP_USER = 'uid=webldap,ou=apps,dc=example,dc=net'

# LDAP application password
LDAP_WEBLDAP_PASSWD = 'secret'

# Default LDAP groups and roles for created users
LDAP_DEFAULT_GROUPS = ['wiki']
LDAP_DEFAULT_ROLES = ['member']
