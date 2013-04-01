from django.shortcuts import render_to_response
from django.core.context_processors import csrf
from django.http import HttpResponseRedirect, Http404
from django.core.urlresolvers import reverse
from django.contrib.auth import REDIRECT_FIELD_NAME
from accounts import libldap
from forms import LoginForm

# View decorator
def connect_ldap(view, login_url='/login', redirect_field_name=REDIRECT_FIELD_NAME):
    def _view(request, *args, **kwargs):
        if not request.session.get('ldap_connected', False):
            path = request.get_full_path()
            from django.contrib.auth.views import redirect_to_login
            return redirect_to_login(path, login_url, redirect_field_name)
        try:
            l = libldap.initialize(request.session['ldap_uid'],
                    request.session['ldap_password'])
        except libldap.ConnectionError:
            return error(request, 'LDAP connection error')
        return view(request, l=l, *args, **kwargs)
    return _view

def error(request, error_msg):
    return render_to_response('accounts/error.html', { 'error_msg': error_msg })

def login(request, redirect_field_name=REDIRECT_FIELD_NAME):
    error_msg = None
    redirect_to = request.REQUEST.get(redirect_field_name, '/profile')

    if request.method == 'POST':
        f = LoginForm(request.POST)
        if f.is_valid():
            try:
                uid = f.cleaned_data['uid']
                password = f.cleaned_data['password']
                l = libldap.initialize(uid, password)
            except libldap.InvalidCredentials:
                error_msg = 'Invalid credentials'
            except libldap.ConnectionError:
                error_msg = 'Connection error'
            else:
                request.session['ldap_connected'] = True
                request.session['ldap_uid'] = uid
                request.session['ldap_password'] = password
                return HttpResponseRedirect(redirect_to)
    else:
        f = LoginForm()

    c = { 'form': f, 'error_msg': error_msg, redirect_field_name: redirect_to }
    c.update(csrf(request))

    return render_to_response('accounts/login.html', c)

@connect_ldap
def profile(request, l):
    (me_dn, me) = l.me()
    search = l.get('(member=%s)' % me_dn, prefix='ou=associations')

    orgs = [{
        'uid': org['uid'][0],
        'name': org['o'][0],
        'is_owner': me_dn in org['owner']
        } for (org_dn, org) in search]

    return render_to_response('accounts/profile.html',
            {
                'uid': me['uid'][0],
                'name': me['cn'][0],
                'email': me['mail'][0],
                'orgs': orgs,
            })

@connect_ldap
def org(request, l, uid):
    try:
        (org_dn, org) = l.get('(uid=%s)' % uid, prefix='ou=associations')[0]
    except IndexError:
        raise Http404

    if l.binddn not in org['owner']:
        return error(request, 'You\'re not the manager')

    name = org['o'][0]
    try:
        uids = map(lambda dn: libldap.get(dn, 0), org['member'])
    except KeyError:
        members = None
    else:
        search = l.get(libldap.build_filter('|', uids), prefix='ou=users')

        members = [{
            'name': member['cn'][0],
            'owner': member_dn in org['owner']
            } for (member_dn, member) in search]

    return render_to_response('accounts/org.html', { 'name': name, 'members': members })
