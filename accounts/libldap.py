import ldap
from federez_ldap import settings

def get(dn, index):
    return dn.split(',')[index]

def paren(string):
    return '(%s)' % string

def build_filter(op, filters):
    return '(%s%s)' % (op, ''.join(map(paren, filters)))

def encode(string):
    return string.encode('utf8')

def ssha(passwd):
    import base64, getpass, hashlib, os
    passwd = encode(passwd)
    salt = os.urandom(8) # edit the length as you see fit
    return '{SSHA}%s' % base64.b64encode('%s%s' %
           (hashlib.sha1('%s%s' % (passwd, salt)).digest(), salt))

class ConnectionError(Exception):
    pass

class InvalidCredentials(Exception):
    pass

class LibLDAPObject():
    """
    Encapsulate an LDAP connection and major attributes, and provide wrappers
    around the python-ldap library.
    """
    def __init__(self, binddn, passwd, base, uri, starttls=False, cacert=None):
        """
        Create LDAP connection using python-ldap and cache major attributes.
        """
        self.binddn = binddn
        self.base = base
        if cacert:
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, cacert)
        try:
            self.conn = ldap.initialize(uri)
            if starttls:
                self.conn.start_tls_s()
            self.conn.bind_s(binddn, passwd)
        except ldap.INVALID_CREDENTIALS:
            raise InvalidCredentials
        except:
            raise ConnectionError

    def me(self):
        """Return self DN."""
        return self.conn.search_s(self.binddn, ldap.SCOPE_BASE, '(objectClass=*)')[0]

    def member_of(self, group):
        """Determine whether bound user is in given group."""
        search = self.conn.search_s(self.base, ldap.SCOPE_SUBTREE,
            '(& (| (cn=%(group)s) \
                   (uid=%(group)s)) \
                (member=uid=%(uid)s,ou=users,dc=federez,dc=net))'
            % { 'group': group, 'uid': self.uid })
        return search != []

    def get(self, request, prefix=None):
        """
        Perform a search with request as filter.

        An optional prefix is prepended to the base.
        """
        base = self.base
        if prefix:
            base = ','.join([prefix, base])
        search = self.conn.search_s(base, ldap.SCOPE_SUBTREE, request)
        return search

    def add(self, object_class, rdn_type, attrs, prefix=None):
        """
        Add entry referenced by RDN and (prefixed) base with attrs as
        attributes.

        object_class must be present in attrs and values in the attrs
        dictionary must only be lists.
        """
        base = self.base
        if prefix:
            base = ','.join([prefix, base])
        dn = '%s=%s,%s' % (rdn_type, encode(attrs[rdn_type][0]), base)
        modlist = [(k, map(encode, v)) for (k, v) in attrs.iteritems()]
        self.conn.add_s(dn, modlist)

    def set(self, rdn, add={}, replace={}, delete={}, prefix=None):
        """
        Set attributes of entry referenced by RDN and (prefixed) base.

        add contains ADD operations, replace contains REPLACE operations
        (equivalent to delete then add) and delete contains DELETE operations.
        """
        base = self.base
        if prefix:
            base = ','.join([prefix, base])
        dn = ','.join([rdn, base])
        adds = [(ldap.MOD_ADD, k, encode(v)) for k in add for v in add[k]]
        replaces = [(ldap.MOD_REPLACE, k, encode(v)) for k in replace for v in replace[k]]
        deletes = [(ldap.MOD_DELETE, k, encode(v)) for k in delete for v in delete[k]]
        modlist = deletes + replaces + adds
        self.conn.modify_s(dn, modlist)

def initialize(passwd, uid=None):
    """
    Return LibLDAP connection container bound as a user using provided
    credentials.

    If no uid is given, then a special account is used.
    """
    base = settings.LDAP_BASE
    if uid:
        dn = 'uid=%s,ou=users,%s' % (uid, base)
    else:
        dn = ','.join([settings.LDAP_WEBLDAP_USER, base])
    return LibLDAPObject(dn, passwd, base, settings.LDAP_URI,
                         starttls=settings.LDAP_STARTTLS, cacert=settings.LDAP_CACERT)
