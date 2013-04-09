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
from accounts.forms import (LoginForm, ProfileForm, RequestAccountForm, RequestPasswdForm,
                            ProcessAccountForm, ProcessPasswdForm)
from models import Request
from federez_ldap import settings

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
                error_msg = 'Identifiants incorrects'
            except libldap.ConnectionError:
                error_msg = 'Erreur de connexion'
            else:
                request.session['ldap_connected'] = True
                request.session['ldap_uid'] = uid
                request.session['ldap_passwd'] = passwd
                return HttpResponseRedirect(redirect_to)
    else:
        f = LoginForm(label_suffix='')

    c = { 'form': f, 'error_msg': error_msg, redirect_field_name: redirect_to }
    c.update(csrf(request))

    return render_to_response('accounts/login.html', c,
                              context_instance=RequestContext(request))

def logout(request, redirect_field_name=REDIRECT_FIELD_NAME, next=None):
    redirect_to = next or request.REQUEST.get(redirect_field_name, '/')
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
def profile_edit(request, l):
    error_msg = None
    (me_dn, me) = l.me()

    if request.method == 'POST':
        f = ProfileForm(request.POST)
        if f.is_valid():
            name_new = f.cleaned_data['name']
            email_new = f.cleaned_data['email']
            nick_new = f.cleaned_data['nick']
            passwd_new = f.cleaned_data['passwd']
            modlist = {}

            if name_new != me['cn'][0]:
                modlist.update({'cn': [name_new]})
            if nick_new != me['sn'][0]:
                modlist.update({'sn': [nick_new]})
            if passwd_new:
                modlist.update({'userPassword': [passwd_new]})

            l.set('uid=%s' % me['uid'][0], replace=modlist, prefix='ou=users')

            if email_new != me['mail'][0]:
                req = Request()
                req.type = Request.EMAIL
                req.uid = me['uid'][0]
                req.email = email_new
                req.save()

                t = loader.get_template('accounts/email_email_request')
                c = Context({
                        'name': me['cn'][0],
                        'url': request.build_absolute_uri(
                                         reverse(process, kwargs={ 'token': req.token })),
                        'expire_in': '48 heures'
                        })
                send_mail(u'Confirmation email FedeRez', t.render(c), settings.EMAIL_FROM,
                          [req.email], fail_silently=False)

            return HttpResponseRedirect('/')

    else:
        f = ProfileForm(label_suffix='', initial={ 'email': me['mail'][0],
                                                   'name': me['cn'][0],
                                                   'nick': me['sn'][0] })

    c = { 'form': f,
          'name': me['cn'][0],
          'nick': me['sn'][0],
          'email': me['mail'][0],
          'error_msg': error_msg, }
    c.update(csrf(request))

    return render_to_response('accounts/edit.html', c,
                              context_instance=RequestContext(request))

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
        return error(request, 'Vous n\'êtes pas gérant.')

    name = org['o'][0]

    if request.method == 'POST':
        f = RequestAccountForm(request.POST)
        if f.is_valid():
            req = f.save(commit=False)
            req.org_uid = uid
            req.type = Request.ACCOUNT
            req.save()

            t = loader.get_template('accounts/email_account_request')
            c = Context({
                    'name': req.name,
                    'url': request.build_absolute_uri(
                                     reverse(process, kwargs={ 'token': req.token })),
                    'expire_in': '48 heures'
                    })
            send_mail(u'Création de compte FedeRez', t.render(c), settings.EMAIL_FROM,
                      [req.email], fail_silently=False)

            return(HttpResponseRedirect('/org/%s' % uid))
    else:
        f = RequestAccountForm(label_suffix='')

    c = { 'form': f, 'name': name, 'error_msg': error_msg, }
    c.update(csrf(request))

    return render_to_response('accounts/org_add.html', c,
                              context_instance=RequestContext(request))

def passwd(request):
    error_msg = None
    if request.method == 'POST':
        f = RequestPasswdForm(request.POST)
        if f.is_valid():
            req = f.save(commit=False)
            l = libldap.initialize(passwd=settings.LDAP_WEBLDAP_PASSWD)
            try:
                (user_dn, user) = l.get('(&(uid=%s)(mail=%s))' % (req.uid, req.email),
                                        prefix='ou=users')[0]
            except IndexError:
                error_msg = 'Données incorrectes'
            else:
                req.type = Request.PASSWD
                req.save()

                t = loader.get_template('accounts/email_passwd_request')
                c = Context({
                    'name': user['cn'][0],
                    'url': request.build_absolute_uri(
                                     reverse(process, kwargs={ 'token': req.token })),
                    })
                send_mail(u'Changement de mot de passe FedeRez', t.render(c),
                          settings.EMAIL_FROM, [req.email], fail_silently=False)
                return HttpResponseRedirect('/')
    else:
        f = RequestPasswdForm(label_suffix='')

    c = { 'form': f, 'error_msg': error_msg, }
    c.update(csrf(request))

    return render_to_response('accounts/passwd.html', c,
                                  context_instance=RequestContext(request))

def process(request, token):
    valid_reqs = Request.objects.filter(expires_at__gt=timezone.now())
    req = get_object_or_404(valid_reqs, token=token)

    if req.type == Request.ACCOUNT:
        return process_account(request, req)
    elif req.type == Request.PASSWD:
        return process_passwd(request, req)
    elif req.type == Request.EMAIL:
        return process_email(request, req=req)
    else:
        return error(request, 'Entrée incorrecte, contactez un admin')

def process_account(request, req):
    if request.method == 'POST':
        f = ProcessAccountForm(request.POST)
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
        f = ProcessAccountForm(label_suffix='')

    c = { 'form': f }
    c.update(csrf(request))

    return render_to_response('accounts/process_account.html', c,
                              context_instance=RequestContext(request))

def process_passwd(request, req):
    if request.method == 'POST':
        f = ProcessPasswdForm(request.POST)
        if f.is_valid():
            l = libldap.initialize(passwd=settings.LDAP_WEBLDAP_PASSWD)
            l.set('uid=%s' % req.uid,
                  replace={ 'userPassword': [libldap.ssha(f.cleaned_data['passwd'])] },
                  prefix='ou=users')

            req.delete()
            return HttpResponseRedirect('/')
    else:
        f = ProcessPasswdForm(label_suffix='')

    c = { 'form': f }
    c.update(csrf(request))

    return render_to_response('accounts/process_passwd.html', c,
                              context_instance=RequestContext(request))

@connect_ldap
def process_email(request, l, req):
    # User who requested email change must be logged in
    if l.binddn != 'uid=%s,ou=users,%s' % (req.uid, l.base):
        logout(request, next=reverse(process, kwargs={ 'token': req.token }))
    l.set('uid=%s' % req.uid, replace={ 'mail': [req.email] }, prefix='ou=users')
    req.delete()
    return HttpResponseRedirect('/')

def help(request):
    return render_to_response('accounts/help.html',
                              context_instance=RequestContext(request))
