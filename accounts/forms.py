# coding=utf8
from django import forms
from accounts.models import Request

def uid_field():
    return forms.CharField(max_length=200,
                            label='identifiant ',
                            widget=forms.TextInput(attrs={ 'placeholder': 'prenom.nom' }))
def passwd_field():
    return forms.CharField(widget=forms.PasswordInput, label='mot de passe')

class LoginForm(forms.Form):
    uid = uid_field()
    passwd = forms.CharField(label='mot de passe',
                             widget=forms.PasswordInput)

class RequestAccountForm(forms.ModelForm):
    uid = uid_field()
    name = forms.CharField(max_length=200,
                           label='nom ',
                           widget=forms.TextInput(attrs={ 'placeholder': 'Prénom Nom' }))
    class Meta:
        model = Request
        fields = ('uid', 'email', 'name')

class RequestPasswdForm(forms.ModelForm):
    uid = uid_field()
    class Meta:
        model = Request
        fields = ('uid', 'email')

class ProcessAccountForm(forms.Form):
    nick = forms.CharField(max_length=100, label='pseudo')
    passwd = passwd_field()
    class Meta:
        fields = ('nick', 'passwd')

class ProcessPasswdForm(forms.Form):
    passwd = passwd_field()
