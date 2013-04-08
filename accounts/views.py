# coding=utf8
from django.shortcuts import render_to_response, get_object_or_404
from django.template import Context, RequestContext, loader
from django.core.context_processors import csrf
from django.http import HttpResponseRedirect, Http404
from django.core.urlresolvers import reverse
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.core.mail import send_mail
from django.utils import timezone
from accounts import libldap
from accounts.forms import LoginForm, OrgAddForm, AccountCreateForm
from models import Request
from federez_ldap import settings

import uuid

# Context processor
def session_info(request):
    return { 'logged_in': request.session.get('ldap_connected', False),
             'logged_uid': request.session.get('ldap_uid', None) }

# View decorator
def connect_ldap(view, login_url='/login', redirect_field_name=REDIRECT_FIELD_NAME):
    def _view(request, *args, **kwargs):
        if not request.session.get('ldap_connected', False):
            path = request.get_full_path()
            from django.contrib.auth.views import redirect_to_login
            return redirect_to_login(path, login_url, redirect_field_name)
        try:
            l = libldap.initialize(request.session['ldap_passwd'],
                    request.session['ldap_uid'])
        except libldap.InvalidCredentials:
            return logout(request, redirect_field_name)
        except libldap.ConnectionError:
            return error(request, 'LDAP connection error')
        return view(request, l=l, *args, **kwargs)
    return _view

def error(request, error_msg):
    return render_to_response('accounts/error.html', { 'error_msg': error_msg },
                              context_instance=RequestContext(request))

def login(request, redirect_field_name=REDIRECT_FIELD_NAME):
    error_msg = None
    redirect_to = request.REQUEST.get(redirect_field_name, '/')

    if request.method == 'POST':
        f = LoginForm(request.POST)
        if f.is_valid():
            try:
                uid = f.cleaned_data['uid']
                passwd = f.cleaned_data['passwd']
                l = libldap.initialize(passwd, uid)
            except libldap.InvalidCredentials:
                error_msg = 'Invalid credentials'
            except libldap.ConnectionError:
                error_msg = 'Connection error'
            else:
                request.session['ldap_connected'] = True
                request.session['ldap_uid'] = uid
                request.session['ldap_passwd'] = passwd
                return HttpResponseRedirect(redirect_to)
    else:
        f = LoginForm()

    c = { 'form': f, 'error_msg': error_msg, redirect_field_name: redirect_to }
    c.update(csrf(request))

    return render_to_response('accounts/login.html', c,
                              context_instance=RequestContext(request))

def logout(request, redirect_field_name=REDIRECT_FIELD_NAME):
    redirect_to = request.REQUEST.get(redirect_field_name, '/')
    request.session.flush()

    return HttpResponseRedirect(redirect_to)

@connect_ldap
def profile(request, l):
    (me_dn, me) = l.me()
    search = l.get('(member=%s)' % me_dn, prefix='ou=associations')

    orgs = [{
        'uid': org['uid'][0],
        'name': org['o'][0],
        'is_owner': me_dn in org['owner']
        } for (org_dn, org) in search]

    search = l.get('(member=%s)' % me_dn, prefix='ou=groups')

    groups = [{
        'name': group['cn'][0],
        } for (group_dn, group) in search]

    return render_to_response('accounts/profile.html',
            {
                'uid': me['uid'][0],
                'name': me['cn'][0],
                'nick': me['sn'][0],
                'email': me['mail'][0],
                'orgs': orgs,
                'groups': groups,
            }, context_instance=RequestContext(request))

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

    return render_to_response('accounts/org.html', { 'name': name, 'members': members },
                              context_instance=RequestContext(request))

@connect_ldap
def org_add(request, l, uid):
    error_msg = None
    try:
        (org_dn, org) = l.get('(uid=%s)' % uid, prefix='ou=associations')[0]
    except IndexError:
        raise Http404

    if l.binddn not in org['owner']:
        return error(request, 'You\'re not the manager')

    name = org['o'][0]

    if request.method == 'POST':
        f = OrgAddForm(request.POST)
        if f.is_valid():
            req = f.save(commit=False)
            req.token = str(uuid.uuid4()).translate(None, '-') # remove hyphens
            req.org_uid = uid
            req.type = Request.ACCOUNT
            req.save()

            t = loader.get_template('accounts/email_account_request')
            c = Context({
                    'name': req.name,
                    'url': request.build_absolute_uri(
                                     reverse(create, kwargs={ 'token': req.token })),
                    'expire_in': '48 heures'
                    })
            send_mail(u'Création de compte FedeRez', t.render(c), settings.EMAIL_FROM,
                      [req.email], fail_silently=False)

            return(HttpResponseRedirect('/org/%s' % uid))
    else:
        f = OrgAddForm()

    c = { 'form': f, 'name': name, 'error_msg': error_msg, }
    c.update(csrf(request))

    return render_to_response('accounts/org_add.html', c,
                              context_instance=RequestContext(request))

def create(request, token):
    valid_reqs = Request.objects.filter(expires_at__gt=timezone.now())
    req = get_object_or_404(valid_reqs, token=token)

    if req.type == Request.ACCOUNT:
        return process_account(request, req)
    else:
        return error(request, 'Entrée incorrecte, contactez un admin')

def process_account(request, req):
    if request.method == 'POST':
        f = AccountCreateForm(request.POST)
        if f.is_valid():
            l = libldap.initialize(passwd=settings.LDAP_WEBLDAP_PASSWD)
            l.add('inetOrgPerson', 'uid',
                  { 'objectClass': ['inetOrgPerson'],
                    'uid': [req.uid],
                    'cn': [req.name],
                    'mail': [req.email],
                    'sn': [f.cleaned_data['nick']],
                    'userPassword': [libldap.ssha(f.cleaned_data['passwd'])]
                  }, prefix='ou=users')

            uid = 'uid=%s,ou=users,%s' % (req.uid, l.base)
            if req.org_uid:
                l.set('uid=%s' % req.org_uid,
                      add={ 'member': [uid] },
                      prefix='ou=associations')
            for group in settings.LDAP_DEFAULT_GROUPS:
                l.set('cn=%s' % group,
                      add={ 'member': [uid] },
                      prefix='ou=groups')

            req.delete()
            return HttpResponseRedirect('/')
    else:
        f = AccountCreateForm()

    c = { 'form': f }
    c.update(csrf(request))

    return render_to_response('accounts/create.html', c,
                              context_instance=RequestContext(request))

def help(request):
    return render_to_response('accounts/help.html',
                              context_instance=RequestContext(request))
