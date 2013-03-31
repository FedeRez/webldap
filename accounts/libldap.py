import ldap

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

def initialize(uid, passwd):
    return LibLDAPObject('uid=%s,ou=users,dc=federez,dc=net' % uid, passwd,
            'dc=federez,dc=net',
            'ldap://ldap.federez.net', True,
            '/etc/ssl/certs/StartCom_Certification_Authority.pem')
