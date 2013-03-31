import ldap

class ConnectionError(Exception):
    pass

class LibLDAPObject():
    def __init__(self, uid, password):
        self.uid = uid
        ldap.set_option(ldap.OPT_X_TLS_CACERTFILE,
            '/etc/ssl/certs/StartCom_Certification_Authority.pem')
        self.conn = ldap.initialize('ldap://ldap.federez.net')
        self.conn.start_tls_s()
        try:
            self.conn.bind_s('uid=%s,ou=users,dc=federez,dc=net' % uid, password)
        except ldap.INVALID_CREDENTIALS:
            raise ConnectionError

    def lookupme(self):
        (dn, entry) = self.conn.search_s('dc=federez,dc=net', ldap.SCOPE_SUBTREE,
                '(uid=%s)' % self.uid)[0]
        return (dn, entry)
