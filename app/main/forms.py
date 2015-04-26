from django import forms
from main.models import Request

def uid_field():
    return forms.CharField(max_length=200,
                           label='identifiant ',
                           widget=forms.TextInput(attrs={ 'placeholder': 'prenom.nom' }))
def passwd_field(required=True):
    return forms.CharField(
        widget=forms.PasswordInput(attrs={ 'placeholder': '8 caractères minimum' }),
        label='mot de passe', required=required)

def passwd_confirm_field(required=True):
    return forms.CharField(
        widget=forms.PasswordInput(attrs={ 'placeholder': 'répéter le mot de passe' }),
        label='', required=required)

def name_field():
    return forms.CharField(max_length=200, label='nom ',
                           widget=forms.TextInput(attrs={ 'placeholder': 'Prénom Nom' }))

def nick_field():
    return forms.CharField(max_length=100, label='pseudo')

class PasswordCheckMixin(forms.Form):
    def clean(self):
        cleaned_data = super(forms.Form, self).clean()
        passwd = cleaned_data.get('passwd')
        passwd_confirm = cleaned_data.get('passwd_confirm')

        if passwd != passwd_confirm:
            raise forms.ValidationError('Mots de passe différents')

        return cleaned_data

class LoginForm(forms.Form):
    uid = uid_field()
    passwd = forms.CharField(label='mot de passe',
                             widget=forms.PasswordInput)

class ProfileForm(PasswordCheckMixin, forms.Form):
    name = name_field()
    nick = nick_field()
    email = forms.EmailField(max_length=254)
    passwd = passwd_field(required=False)
    passwd_confirm = passwd_confirm_field(required=False)

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

class ProcessAccountForm(PasswordCheckMixin, forms.Form):
    nick = nick_field()
    passwd = passwd_field()
    passwd_confirm = passwd_confirm_field()

class ProcessPasswdForm(PasswordCheckMixin, forms.Form):
    passwd = passwd_field()
    passwd_confirm = passwd_confirm_field()
