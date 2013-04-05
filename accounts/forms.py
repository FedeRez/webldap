from django import forms
from accounts.models import AccountRequest

class LoginForm(forms.Form):
    uid = forms.CharField(max_length=200)
    password = forms.CharField(widget=forms.PasswordInput)

class OrgAddForm(forms.ModelForm):
    class Meta:
        model = AccountRequest
        exclude = ('token', 'org_uid', 'created_at')

class AccountCreateForm(forms.Form):
    nick = forms.CharField(max_length=100)
    passwd = forms.CharField(widget=forms.PasswordInput)
