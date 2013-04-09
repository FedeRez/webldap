# coding=utf8
from django import forms
from accounts.models import Request

def uid_field():
    return forms.CharField(max_length=200,
                            label='identifiant ',
                            widget=forms.TextInput(attrs={ 'placeholder': 'prenom.nom' }))
def passwd_field():
    return forms.CharField(widget=forms.PasswordInput, label='mot de passe')

def name_field():
    return forms.CharField(max_length=200,
                           label='nom ',
                       widget=forms.TextInput(attrs={ 'placeholder': 'Prénom Nom' }))

def nick_field():
    return forms.CharField(max_length=100, label='pseudo')

class LoginForm(forms.Form):
    uid = uid_field()
    passwd = forms.CharField(label='mot de passe',
                             widget=forms.PasswordInput)

class ProfileForm(forms.Form):
    name = name_field()
    nick = nick_field()
    email = forms.EmailField(max_length=254)
    passwd = forms.CharField(
             widget=forms.PasswordInput(attrs={ 'placeholder': 'uniquement si nouveau' }),
             required=False,
             label='mot de passe')

class RequestAccountForm(forms.ModelForm):
    uid = uid_field()
    name = name_field()
    class Meta:
        model = Request
        fields = ('uid', 'email', 'name')

class RequestPasswdForm(forms.ModelForm):
    uid = uid_field()
    class Meta:
        model = Request
        fields = ('uid', 'email')

class ProcessAccountForm(forms.Form):
    nick = nick_field()
    passwd = passwd_field()

class ProcessPasswdForm(forms.Form):
    passwd = passwd_field()
