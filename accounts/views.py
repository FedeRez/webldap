from django.shortcuts import render_to_response
from django.core.context_processors import csrf
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.contrib.auth import REDIRECT_FIELD_NAME
from accounts import libldap
from forms import LoginForm

# View decorator
def connect_ldap(view, login_url='/login', redirect_field_name=REDIRECT_FIELD_NAME):
    def _view(request):
        if not request.session.get('ldap_connected', False):
            path = request.get_full_path()
            from django.contrib.auth.views import redirect_to_login
            return redirect_to_login(path, login_url, redirect_field_name)
        try:
            l = libldap.LibLDAPObject(request.session['ldap_uid'],
                    request.session['ldap_password'])
        except libldap.ConnectionError:
            return error(request, 'LDAP connection error')
        return view(request, l)
    return _view

def error(request, error_msg):
    return render_to_response('accounts/error.html', { 'error_msg': error_msg })

def test(request):
    return render_to_response('accounts/test.html')

def login(request, redirect_field_name=REDIRECT_FIELD_NAME):
    error_msg = None
    redirect_to = request.REQUEST.get(redirect_field_name, '/profile')

    if request.method == 'POST':
        f = LoginForm(request.POST)
        if f.is_valid():
            try:
                uid = f.cleaned_data['uid']
                password = f.cleaned_data['password']
                l = libldap.get_conn(uid, password)
            except libldap.ConnectionError:
                error_msg = 'Invalid credentials'
            else:
                l.unbind_s()
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
    (dn, entry) = l.lookupme()
    return render_to_response('accounts/profile.html', { 'uid': entry['uid'][0] })
