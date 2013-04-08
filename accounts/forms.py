from django import forms
from accounts.models import Request

class LoginForm(forms.Form):
    uid = forms.CharField(max_length=200)
    passwd = forms.CharField(widget=forms.PasswordInput)

class RequestAccountForm(forms.ModelForm):
    class Meta:
        model = Request
        fields = ('uid', 'email', 'name')

class RequestPasswdForm(forms.ModelForm):
    class Meta:
        model = Request
        fields = ('uid', 'email')

class ProcessAccountForm(forms.Form):
    nick = forms.CharField(max_length=100)
    passwd = forms.CharField(widget=forms.PasswordInput)

class ProcessPasswdForm(forms.Form):
    passwd = forms.CharField(widget=forms.PasswordInput)
