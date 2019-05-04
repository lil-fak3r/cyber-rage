from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import (
    UserCreationForm,
    AuthenticationForm,
    ReadOnlyPasswordHashField,
)

User = get_user_model()


class SignupForm(UserCreationForm):
    email = forms.EmailField(max_length=40, widget=forms.EmailInput(
        attrs={
            "id": "emailInput",
            "class": "form-control shadow-none rounded-0",
            "placeholder": "Enter email address"
        }
    ))
    username = forms.CharField(max_length=40, widget=forms.TextInput(
        attrs={
            "id": "usernameInput",
            "class": "form-control shadow-none rounded-0",
            "placeholder": "Enter username"
        }
    ))
    password1 = forms.CharField(max_length=40, widget=forms.PasswordInput(
        attrs={
            "id": "pass1Input",
            "class": "form-control shadow-none rounded-0",
            "placeholder": "Password"
        }
    ))
    password2 = forms.CharField(max_length=40, widget=forms.PasswordInput(
        attrs={
            "id": "pass2Input",
            "class": "form-control shadow-none rounded-0",
            "placeholder": "Confirm pass"
        }
    ))

    class Meta:
        model = User
        fields = ("email", "username", "password1", "password2")


class LoginForm(forms.Form):
    email = forms.EmailField(
        max_length=40,
        widget=forms.EmailInput(
            attrs={
                "id": "emailInput",
                "class": "form-control shadow-none rounded-0",
                "placeholder": "Enter email address",
            }
        ),
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "id": "passInput",
                "class": "form-control shadow-none rounded-0",
                "placeholder": "Enter password",
            }
        ),
    )
    two_fa = forms.CharField(
        max_length=6,
        widget=forms.TextInput(
            attrs={
                "id": "2FA",
                "class": "form-control shadow-none rounded-0",
                "placeholder": "Enter 2FA Code",
            }
        ),
    )


class UserAdminCreationForm(forms.ModelForm):
    password1 = forms.CharField(label="Password", widget=forms.PasswordInput)
    password2 = forms.CharField(label="Confirm password", widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ("email", "username")

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")

        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Password don't match")
        return password2

    def save(self, commit=True):
        user = super(UserAdminCreationForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserAdminChangeForm(forms.ModelForm):
    password = ReadOnlyPasswordHashField()

    class Meta:
        model = User
        fields = ("email", "username", "password", "is_active", "is_superuser")

    def clean_password(self):
        return self.initial["password"]
