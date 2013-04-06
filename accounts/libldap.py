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
    def __init__(self, binddn, passwd, base, uri, starttls=False, cacert=None):
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
        return self.conn.search_s(self.binddn, ldap.SCOPE_BASE, '(objectClass=*)')[0]

    def member_of(self, group):
        search = self.conn.search_s(self.base, ldap.SCOPE_SUBTREE,
            '(& (| (cn=%(group)s) \
                   (uid=%(group)s)) \
                (member=uid=%(uid)s,ou=users,dc=federez,dc=net))'
            % { 'group': group, 'uid': self.uid })
        return search != []

    def get(self, request, prefix=None):
        base = self.base
        if prefix:
            base = ','.join([prefix, base])
        search = self.conn.search_s(base, ldap.SCOPE_SUBTREE, request)
        return search

    def add(self, object_class, rdn_type, attrs, prefix=None):
        base = self.base
        if prefix:
            base = ','.join([prefix, base])
        dn = '%s=%s,%s' % (rdn_type, encode(attrs[rdn_type][0]), base)
        modlist = [(k, map(encode, v)) for (k, v) in attrs.iteritems()]
        self.conn.add_s(dn, modlist)

    def set(self, rdn, add={}, replace={}, delete={}, prefix=None):
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
    base = settings.LDAP_BASE
    if uid:
        dn = 'uid=%s,ou=users,%s' % (uid, base)
    else:
        dn = 'cn=admin,%s' % base
    return LibLDAPObject(dn, passwd, base, 'ldap://ldap.federez.net', True,
                         '/etc/ssl/certs/StartCom_Certification_Authority.pem')
