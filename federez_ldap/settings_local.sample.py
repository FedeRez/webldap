# Local settings

DEBUG = True
TEMPLATE_DEBUG = DEBUG

# Make this unique, and don't share it with anybody.
SECRET_KEY = '&amp;%_)uh4i3u%7fmcm98$tu+r03619eb!qqrwzhk92%eyl0@tdt5'

TEMPLATE_DIRS = (
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

# Settings specific to 'accounts'

# SMTP relay (host and port) to use for confirmation mails
EMAIL_HOST = 'incoming-relays.illinois.edu'
EMAIL_PORT = 25

# LDAP base
LDAP_BASE = 'dc=example,dc=org'

# LDAP application user password
LDAP_ADMIN_PASSWD = 'obvrajtz'

# Default LDAP groups for created users
LDAP_DEFAULT_GROUPS = ['wiki']
