import ldap

class ConnectionError(Exception):
    pass

def get_conn(uid, password):
    ldap.set_option(ldap.OPT_X_TLS_CACERTFILE,
        '/etc/ssl/certs/StartCom_Certification_Authority.pem')
    l = ldap.initialize('ldap://ldap.federez.net')
    l.start_tls_s()
    try:
        l.bind_s('uid=%s,ou=users,dc=federez,dc=net' % uid, password)
    except ldap.INVALID_CREDENTIALS:
        raise ConnectionError

    return l

