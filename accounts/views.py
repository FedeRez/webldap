# coding=utf8
from django.shortcuts import render_to_response, get_object_or_404
from django.template import Context, RequestContext, loader
from django.core.context_processors import csrf
from django.http import HttpResponseRedirect, Http404
from django.core.urlresolvers import reverse
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.core.mail import send_mail
from django.utils import timezone
from accounts.forms import (LoginForm, ProfileForm, RequestAccountForm, RequestPasswdForm,
                            ProcessAccountForm, ProcessPasswdForm)
from models import Request
from federez_ldap import settings
import ldapom

# Context processor
def session_info(request):
    return { 'logged_in': request.session.get('ldap_connected', False),
             'logged_uid': request.session.get('ldap_binduid', None) }

# View decorator
def connect_ldap(view, login_url='/login', redirect_field_name=REDIRECT_FIELD_NAME):
    def _view(request, *args, **kwargs):
        if not request.session.get('ldap_connected', False):
            path = request.get_full_path()
            from django.contrib.auth.views import redirect_to_login
            return redirect_to_login(path, login_url, redirect_field_name)
        try:
            l = ldapom.LdapConnection(uri=settings.LDAP_URI,
                    base=settings.LDAP_BASE,
                    login=request.session['ldap_binddn'],
                    password=request.session['ldap_passwd'])
        except (KeyError, ldapom.ldap.INVALID_CREDENTIALS):
            return logout(request, redirect_field_name)
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
            request.session['ldap_connected'] = True
            request.session['ldap_binduid'] = f.cleaned_data['uid']
            request.session['ldap_binddn'] = 'uid=%s,ou=users,%s' \
                                             % (f.cleaned_data['uid'], settings.LDAP_BASE)
            request.session['ldap_passwd'] = f.cleaned_data['passwd']
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
    me = l.get_ldap_node(request.session['ldap_binddn'])

    search = l.search('uniqueMember=%s' % me.dn, base='ou=associations,%s' % settings.LDAP_BASE)
    orgs = [{
        'uid': org.o,
        'name': org.cn,
        'is_owner': me.dn in org.owner
        } for org in search]

    search = list(l.search('uniqueMember=%s'
                           % me.dn, base='ou=accesses,ou=groups,%s' % settings.LDAP_BASE))
    search.extend(l.search('roleOccupant=%s'
                           % me.dn, base='ou=roles,%s' % settings.LDAP_BASE))

    groups = [{
        'name': group.cn,
        } for group in search]

    return render_to_response('accounts/profile.html',
            {
                'uid': me.uid,
                'name': me.displayName,
                'nick': me.cn,
                'email': me.mail,
                'orgs': orgs,
                'groups': groups,
            }, context_instance=RequestContext(request))

@connect_ldap
def profile_edit(request, l):
    error_msg = None
    me = l.get_ldap_node(request.session['ldap_binddn'])

    if request.method == 'POST':
        f = ProfileForm(request.POST)
        if f.is_valid():
            me.displayName = f.cleaned_data['name']
            me.cn = f.cleaned_data['nick']
            me.save()

            passwd_new = f.cleaned_data['passwd']
            email_new = f.cleaned_data['email']

            if passwd_new:
                me.set_password(passwd_new)
                request.session['ldap_passwd'] = passwd_new

            if email_new != str(me.mail):
                req = Request()
                req.type = Request.EMAIL
                req.uid = me.uid
                req.email = email_new
                req.save()

                t = loader.get_template('accounts/email_email_request')
                c = Context({
                        'name': me.displayName,
                        'url': request.build_absolute_uri(
                                         reverse(process, kwargs={ 'token': req.token })),
                        'expire_in': settings.REQ_EXPIRE_STR,
                        })
                send_mail(u'Confirmation email FedeRez', t.render(c), settings.EMAIL_FROM,
                          [req.email], fail_silently=False)

            return HttpResponseRedirect('/')

    else:
        f = ProfileForm(label_suffix='', initial={ 'email': me.mail,
                                                   'name': me.displayName,
                                                   'nick': me.cn })

    c = { 'form': f,
          'name': me.displayName,
          'nick': me.cn,
          'email': me.mail,
          'error_msg': error_msg, }
    c.update(csrf(request))

    return render_to_response('accounts/edit.html', c,
                              context_instance=RequestContext(request))

@connect_ldap
def org(request, l, uid):
    try:
        org = l.retrieve_ldap_node('o=%s,ou=associations,%s' % (uid, settings.LDAP_BASE))
    except ldapom.ldap.NO_SUCH_OBJECT:
        raise Http404

    search = [l.get_ldap_node(dn) for dn in org.uniqueMember]

    members = [{
        'uid': member.uid,
        'name': member.displayName,
        'owner': member.dn in org.owner,
        } for member in search]

    return render_to_response('accounts/org.html',
                              { 'uid': uid,
                                'name': org.cn,
                                'is_owner': request.session['ldap_binddn'] in org.owner,
                                'members': members },
                              context_instance=RequestContext(request))

@connect_ldap
def org_promote(request, l, uid, user_uid):
    try:
        org = l.retrieve_ldap_node('o=%s,ou=associations,%s' % (uid, settings.LDAP_BASE))
        user = l.retrieve_ldap_node('uid=%s,ou=users,%s' % (user_uid, settings.LDAP_BASE))
    except ldapom.ldap.NO_SUCH_OBJECT:
        raise Http404

    if request.session['ldap_binddn'] not in org.owner:
        return error(request, 'Vous n\'êtes pas gérant.')

    org.owner.append(user.dn)
    org.save()

    return render_to_response('accounts/org_promote.html',
                              { 'uid': org.o,
                                'name': org.cn,
                                'user_name': user.displayName })

@connect_ldap
def org_add(request, l, uid):
    error_msg = None
    try:
        org = l.retrieve_ldap_node('o=%s,ou=associations,%s' % (uid, settings.LDAP_BASE))
    except ldapom.ldap.NO_SUCH_OBJECT:
        raise Http404

    if request.session['ldap_binddn'] not in org.owner:
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
            send_mail(u'Création de compte FedeRez', t.render(c), settings.EMAIL_FROM,
                      [req.email], fail_silently=False)

            return HttpResponseRedirect('/org/%s' % uid)
    else:
        f = RequestAccountForm(label_suffix='')

    c = { 'form': f, 'name': org.cn, 'uid': uid, 'error_msg': error_msg }
    c.update(csrf(request))

    return render_to_response('accounts/org_add.html', c,
                              context_instance=RequestContext(request))

def passwd(request):
    error_msg = None
    if request.method == 'POST':
        f = RequestPasswdForm(request.POST)
        if f.is_valid():
            req = f.save(commit=False)
            l = ldapom.LdapConnection(uri=settings.LDAP_URI,
                    base=settings.LDAP_BASE,
                    login=settings.LDAP_WEBLDAP_USER,
                    password=settings.LDAP_WEBLDAP_PASSWD)
            try:
                user = list(l.search('(&(uid=%s)(mail=%s))' % (req.uid, req.email),
                               base='ou=users,%s' % settings.LDAP_BASE))[0]
            except IndexError:
                error_msg = 'Données incorrectes'
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
                send_mail(u'Changement de mot de passe FedeRez', t.render(c),
                          settings.EMAIL_FROM, [user.email], fail_silently=False)
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
    error_msg = u''
    if request.method == 'POST':
        f = ProcessAccountForm(request.POST)
        if f.is_valid():
            l = ldapom.LdapConnection(uri=settings.LDAP_URI,
                    base=settings.LDAP_BASE,
                    login=settings.LDAP_WEBLDAP_USER,
                    password=settings.LDAP_WEBLDAP_PASSWD)
            user = l.new_ldap_node('uid=%s,ou=users,%s' % (req.uid, settings.LDAP_BASE))
            user.objectclass = 'inetOrgPerson'
            user.uid = req.uid
            user.displayName = req.name
            user.mail = req.email
            user.cn = f.cleaned_data['nick']
            user.sn = 'CHANGEIT!' # TODO
            try:
                user.save()
                user.set_password(f.cleaned_data['passwd'])

                if req.org_uid:
                    org = l.get_ldap_node('o=%s,ou=associations,%s' \
                                          % (req.org_uid, settings.LDAP_BASE))
                    org.uniqueMember.append(user.dn)
                    org.save()

                for group in settings.LDAP_DEFAULT_GROUPS:
                    group = l.get_ldap_node('cn=%s,ou=accesses,ou=groups,%s' \
                                            % (group, settings.LDAP_BASE))
                    group.uniqueMember.append(user.dn)
                    group.save()

                for role in settings.LDAP_DEFAULT_ROLES:
                    role = l.get_ldap_node('cn=%s,ou=roles,%s' \
                                           % (role, settings.LDAP_BASE))
                    role.roleOccupant.append(user.dn)
                    role.save()

                req.delete()
            except ldapom.ldap.CONSTRAINT_VIOLATION, e:
                # Parse LDAP constraint violation exceptions to give meaningful information
                error = e.args[0]
                if error['info'] == 'some attributes not unique':
                    error_msg = u'Pseudo déjà pris'
                elif error['info'] == u'Password fails quality checking policy':
                    error_msg = u'Mot de passe trop faible'
                    user.delete()
                else:
                    raise e
            except ldapom.ldap.ALREADY_EXISTS:
                error_msg = u'Compte déjà créé'
            else:
                # Everything went well
                return HttpResponseRedirect('/')

            c = { 'form': f, 'error_msg': error_msg }
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
        logout(request, next=reverse(process, kwargs={ 'token': req.token }))
    user = l.get_ldap_node(request.session['ldap_binddn'])
    user.mail = req.email
    user.save()

    req.delete()
    return HttpResponseRedirect('/')

def help(request):
    return render_to_response('accounts/help.html',
                              context_instance=RequestContext(request))
