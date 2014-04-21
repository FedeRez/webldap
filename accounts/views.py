# coding=utf8
from django.shortcuts import render_to_response, get_object_or_404
from django.template import Context, RequestContext, loader
from django.core.context_processors import csrf
from django.http import HttpResponseRedirect, Http404
from django.core.urlresolvers import reverse
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.core.mail import send_mail
from django.utils import timezone
from django.contrib import messages
from .forms import (LoginForm, ProfileForm, RequestAccountForm, RequestPasswdForm,
                            ProcessAccountForm, ProcessPasswdForm)
from .models import Request
from federez_ldap import settings
import ldapom

def one(singleton):
    (e,) = singleton
    return e

# Context processor
def session_info(request):
    return { 'logged_in': request.session.get('ldap_connected', False),
             'logged_uid': request.session.get('ldap_binduid', None),
             'is_admin': request.session.get('is_admin', False) }

# View decorator
def connect_ldap(view, login_url='/login', redirect_field_name=REDIRECT_FIELD_NAME):
    def _view(request, *args, **kwargs):
        if not request.session.get('ldap_connected', False):
            path = request.get_full_path()
            from django.contrib.auth.views import redirect_to_login
            return redirect_to_login(path, login_url, redirect_field_name)
        try:
            l = ldapom.LDAPConnection(uri=settings.LDAP_URI,
                    base=settings.LDAP_BASE,
                    bind_dn=request.session['ldap_binddn'],
                    bind_password=request.session['ldap_passwd'])
        except (KeyError, ldapom.error.LDAPInvalidCredentialsError):
            return logout(request, redirect_field_name)

        # Login successful, check if admin
        if request.session.get('is_admin', None) is None:
            admins = l.get_entry(
                    'cn=admin,ou=roles,%s' % settings.LDAP_BASE).roleOccupant
            request.session['is_admin'] = request.session['ldap_binddn'] in admins

        return view(request, l=l, *args, **kwargs)
    return _view

def error(request, error_msg):
    return render_to_response('accounts/error.html', { 'error_msg': error_msg },
                              context_instance=RequestContext(request))

def login(request, redirect_field_name=REDIRECT_FIELD_NAME):
    redirect_to = request.REQUEST.get(redirect_field_name, '/')

    if request.method == 'POST':
        f = LoginForm(request.POST)
        if f.is_valid():
            request.session['ldap_connected'] = True
            request.session['ldap_binduid'] = f.cleaned_data['uid']
            request.session['ldap_binddn'] = 'uid=%s,ou=users,%s' \
                                             % (f.cleaned_data['uid'], settings.LDAP_BASE)
            request.session['ldap_passwd'] = f.cleaned_data['passwd']
            return HttpResponseRedirect(redirect_to)
    else:
        f = LoginForm(label_suffix='')

    c = { 'form': f, redirect_field_name: redirect_to }
    c.update(csrf(request))

    return render_to_response('accounts/login.html', c,
                              context_instance=RequestContext(request))

def logout(request, redirect_field_name=REDIRECT_FIELD_NAME, next=None):
    redirect_to = next or request.REQUEST.get(redirect_field_name, '/')
    request.session.flush()

    return HttpResponseRedirect(redirect_to)

@connect_ldap
def profile(request, l):
    me = l.get_entry(request.session['ldap_binddn'])

    search = l.search('uniqueMember=%s' % me.dn, base='ou=associations,%s' % settings.LDAP_BASE)
    orgs = [{
        'uid': one(org.o),
        'name': one(org.cn),
        'is_owner': me.dn in org.owner
        } for org in search]

    search = list(l.search('uniqueMember=%s'
                           % me.dn, base='ou=accesses,ou=groups,%s' % settings.LDAP_BASE))
    search.extend(l.search('roleOccupant=%s'
                           % me.dn, base='ou=roles,%s' % settings.LDAP_BASE))

    groups = [{
        'name': one(group.cn),
        } for group in search]

    return render_to_response('accounts/profile.html',
            {
                'uid': me.uid,
                'name': me.displayName,
                'nick': one(me.cn),
                'email': one(me.mail),
                'orgs': orgs,
                'groups': groups,
            }, context_instance=RequestContext(request))

@connect_ldap
def profile_edit(request, l):
    me = l.get_entry(request.session['ldap_binddn'])

    if request.method == 'POST':
        f = ProfileForm(request.POST)
        if f.is_valid():
            name = f.cleaned_data['name']
            nick = f.cleaned_data['nick']
            if name != me.displayName or nick != one(me.cn):
                me.displayName = f.cleaned_data['name']
                me.cn = f.cleaned_data['nick']
                me.save()

            passwd_new = f.cleaned_data['passwd']
            email_new = f.cleaned_data['email']

            if passwd_new:
                me.set_password(passwd_new)
                request.session['ldap_passwd'] = passwd_new

            if email_new != one(me.mail):
                req = Request()
                req.type = Request.EMAIL
                req.uid = one(me.uid)
                req.email = email_new
                req.save()

                t = loader.get_template('accounts/email_email_request')
                c = Context({
                        'name': me.displayName,
                        'url': request.build_absolute_uri(
                                         reverse(process, kwargs={ 'token': req.token })),
                        'expire_in': settings.REQ_EXPIRE_STR,
                        })
                send_mail('Confirmation email FedeRez', t.render(c), settings.EMAIL_FROM,
                          [req.email], fail_silently=False)
                messages.success(request, 'Un email vous a été envoyé pour confirmer votre nouvelle adresse email')

            return HttpResponseRedirect('/')

    else:
        f = ProfileForm(label_suffix='', initial={ 'email': one(me.mail),
                                                   'name': me.displayName,
                                                   'nick': one(me.cn) })

    c = { 'form': f,
          'name': me.displayName,
          'nick': one(me.cn),
          'email': one(me.mail) }
    c.update(csrf(request))

    return render_to_response('accounts/edit.html', c,
                              context_instance=RequestContext(request))

@connect_ldap
def org(request, l, uid):
    org = l.get_entry('o=%s,ou=associations,%s' % (uid, settings.LDAP_BASE))

    if not org.exists():
        raise Http404

    search = [l.get_entry(dn) for dn in org.uniqueMember]

    members = [{
        'uid': one(member.uid),
        'name': member.displayName,
        'owner': member.dn in org.owner,
        } for member in search]

    return render_to_response('accounts/org.html',
                              { 'uid': uid,
                                'name': one(org.cn),
                                'is_owner': request.session['ldap_binddn'] in org.owner,
                                'members': members },
                              context_instance=RequestContext(request))

@connect_ldap
def org_promote(request, l, uid, user_uid):
    org = l.get_entry('o=%s,ou=associations,%s' % (uid, settings.LDAP_BASE))
    user = l.get_entry('uid=%s,ou=users,%s' % (user_uid, settings.LDAP_BASE))

    if not org.exists() or not user.exists():
        raise Http404

    if request.session['ldap_binddn'] not in org.owner \
    and not request.session['is_admin']:
        messages.error(request, 'Vous n\'êtes ni gérant, ni admin')
        return HttpResponseRedirect('/org/{}'.format(uid))

    org.owner.add(user.dn)
    org.save()

    messages.success(request, '{} est désormais gérant'.format(user.displayName))
    return HttpResponseRedirect('/org/{}'.format(uid))

@connect_ldap
def org_relegate(request, l, uid, user_uid):
    org = l.get_entry('o=%s,ou=associations,%s' % (uid, settings.LDAP_BASE))
    user = l.get_entry('uid=%s,ou=users,%s' % (user_uid, settings.LDAP_BASE))

    if not org.exists() or not user.exists():
        raise Http404

    if request.session['ldap_binddn'] not in org.owner \
    and not request.session['is_admin']:
        messages.error(request, 'Vous n\'êtes ni gérant, ni admin')
        return HttpResponseRedirect('/org/{}'.format(uid))

    org.owner.discard(user.dn)
    org.save()

    messages.success(request, '{} n\'est plus gérant'.format(user.displayName))
    return HttpResponseRedirect('/org/{}'.format(uid))

@connect_ldap
def org_add(request, l, uid):
    org = l.get_entry('o=%s,ou=associations,%s' % (uid, settings.LDAP_BASE))
    if not org.exists():
        raise Http404

    if request.session['ldap_binddn'] not in org.owner \
       and not request.session['is_admin']:
        return error(request, 'Vous n\'êtes pas gérant.')

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
                    'expire_in': settings.REQ_EXPIRE_STR,
                    })
            send_mail('Création de compte FedeRez', t.render(c), settings.EMAIL_FROM,
                      [req.email], fail_silently=False)
            messages.success(request, 'Email envoyé à %s pour la création du compte' % req.email)

            return HttpResponseRedirect('/org/%s' % uid)
    else:
        f = RequestAccountForm(label_suffix='')

    c = { 'form': f,
          'name': one(org.cn),
          'uid': uid }
    c.update(csrf(request))

    return render_to_response('accounts/org_add.html', c,
                              context_instance=RequestContext(request))

@connect_ldap
def admin(request, l):
    me = l.get_entry(request.session['ldap_binddn'])

    if not request.session['is_admin']:
        return error(request, 'Vous n\'êtes pas administrateur')

    search = l.search('(objectClass=groupOfUniqueNames)',
                      base='ou=associations,%s' % settings.LDAP_BASE)
    orgs = [{
        'uid': one(org.o),
        'name': one(org.cn),
        'is_owner': me.dn in org.owner,
        } for org in search]

    return render_to_response('accounts/admin.html',
            {
                'orgs': orgs,
            }, context_instance=RequestContext(request))

def passwd(request):
    if request.method == 'POST':
        f = RequestPasswdForm(request.POST)
        if f.is_valid():
            req = f.save(commit=False)
            l = ldapom.LDAPConnection(uri=settings.LDAP_URI,
                    base=settings.LDAP_BASE,
                    bind_dn=settings.LDAP_WEBLDAP_USER,
                    bind_password=settings.LDAP_WEBLDAP_PASSWD)
            try:
                user = list(l.search('(&(uid=%s)(mail=%s))' % (req.uid, req.email),
                               base='ou=users,%s' % settings.LDAP_BASE))[0]
            except IndexError:
                messages.error(request, 'Données incorrectes')
            else:
                req.type = Request.PASSWD
                req.save()

                t = loader.get_template('accounts/email_passwd_request')
                c = Context({
                    'name': user.displayName,
                    'url': request.build_absolute_uri(
                                     reverse(process, kwargs={ 'token': req.token })),
                    'expire_in': settings.REQ_EXPIRE_STR,
                    })
                send_mail('Changement de mot de passe FedeRez', t.render(c),
                          settings.EMAIL_FROM, [str(user.mail)], fail_silently=False)
                return HttpResponseRedirect('/')
    else:
        f = RequestPasswdForm(label_suffix='')

    c = { 'form': f }
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
            l = ldapom.LDAPConnection(uri=settings.LDAP_URI,
                    base=settings.LDAP_BASE,
                    bind_dn=settings.LDAP_WEBLDAP_USER,
                    bind_password=settings.LDAP_WEBLDAP_PASSWD)
            user = l.get_entry('uid=%s,ou=users,%s' % (req.uid, settings.LDAP_BASE))

            if user.exists():
                messages.error(request, 'Compte déjà créé')
                return HttpResponseRedirect('/')

            user.objectClass = 'inetOrgPerson'
            user.uid = req.uid
            user.displayName = req.name
            user.mail = req.email
            user.cn = f.cleaned_data['nick']
            user.sn = 'CHANGEIT!' # TODO
            try:
                user.save()
                user.set_password(f.cleaned_data['passwd'])

                if req.org_uid:
                    org = l.get_entry('o=%s,ou=associations,%s' \
                                          % (req.org_uid, settings.LDAP_BASE))
                    org.uniqueMember.add(user.dn)
                    org.save()

                for group in settings.LDAP_DEFAULT_GROUPS:
                    group = l.get_entry('cn=%s,ou=accesses,ou=groups,%s' \
                                            % (group, settings.LDAP_BASE))
                    group.uniqueMember.add(user.dn)
                    group.save()

                for role in settings.LDAP_DEFAULT_ROLES:
                    role = l.get_entry('cn=%s,ou=roles,%s' \
                                           % (role, settings.LDAP_BASE))
                    role.roleOccupant.add(user.dn)
                    role.save()

                req.delete()
            except ldapom.error.LDAPError as e:
                if e.args[0] == 'Constraint violation':
                    messages.error(request, 'Pseudo déjà pris')
                else:
                    raise e
            else:
                messages.success(request, 'Compte créé')

                return HttpResponseRedirect('/')

            c = { 'form': f }
            c.update(csrf(request))

            return render_to_response('accounts/process_account.html', c,
                                      context_instance=RequestContext(request))
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
            l = ldapom.LdapConnection(uri=settings.LDAP_URI,
                    base=settings.LDAP_BASE,
                    login=settings.LDAP_WEBLDAP_USER,
                    password=settings.LDAP_WEBLDAP_PASSWD)
            user = l.get_ldap_node('uid=%s,ou=users,%s' % (req.uid, settings.LDAP_BASE))
            user.set_password(f.cleaned_data['passwd'])
            req.delete()
            messages.success(request, 'Mot de passe changé')

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
    if request.session['ldap_binddn'] != 'uid=%s,ou=users,%s' % (req.uid, settings.LDAP_BASE):
        return logout(request, next=reverse(process, kwargs={ 'token': req.token }))
    user = l.get_entry(request.session['ldap_binddn'])
    user.mail = req.email
    user.save()
    req.delete()
    messages.success(request, 'Email confirmé')

    return HttpResponseRedirect('/')

def help(request):
    return render_to_response('accounts/help.html',
                              context_instance=RequestContext(request))
