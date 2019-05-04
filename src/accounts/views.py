import requests
import pyotp

from django.shortcuts import render, redirect, reverse, HttpResponse
from django.contrib.auth import login, authenticate
from django.contrib.auth import get_user_model
from django.contrib.auth.views import LoginView as inV, LogoutView as outV
from django.contrib.auth.forms import UserCreationForm
from django.views.generic import View, DetailView
from django.contrib.auth.mixins import LoginRequiredMixin

from django.conf import settings

from .forms import SignupForm, LoginForm
from .models import User, AuthKey
from .token import account_activation_token

# email import
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.core.mail import EmailMessage, send_mail
from django.template import loader


class SignupView(View):
    def get(self, request):
        form = SignupForm
        return render(request, "accounts/sign_up.html", {"form": form})

    def post(self, request):
        form = SignupForm(request.POST)
        if form.is_valid():

            # start reCAPTCHA validation
            recaptcha_response = request.POST.get("g-recaptcha-response")
            data = {
                "secret": settings.GOOGLE_RECAPTCHA_SECRET_KEY,
                "response": recaptcha_response,
            }
            r = requests.post(
                "https://www.google.com/recaptcha/api/siteverify", data=data
            )
            result = r.json()

            if result["success"]:
                user = form.save(commit=False)
                user.is_active = False
                user.save()
                current_site = get_current_site(request)
                mail_subject = "Activate your account."
                message = render_to_string(
                    "accounts/activate_email.html",
                    {
                        "user": user,
                        "domain": current_site.domain,
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "token": account_activation_token.make_token(user),
                    },
                )
                to_email = form.cleaned_data.get("email")
                email = EmailMessage(mail_subject, message, to=[to_email])
                email.send()
                post_mess = (
                    "Please confirm your email address to complete the registration."
                )
                post_mess2 = "You can now close this tab."
                return render(
                    request, "base/mess.html", {"mess": post_mess, "mess2": post_mess2}
                )

            else:
                return render(request, 'accounts/sign_up.html', {'form': form})
        else:
            return render(request, 'accounts/sign_up.html', {'form': form})

    def activate(request, uidb64, token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is not None and account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            login(request, user)
            return redirect("accounts:mfa")
        else:
            return HttpResponse("Activation link is invalid!")


class MFA(LoginRequiredMixin, View):
    def get(self, request):
        meth = "GET"
        auth_key = pyotp.random_base32()
        QR = f'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl= \
            {pyotp.totp.TOTP(auth_key).provisioning_uri(self.request.user.username, issuer_name="CyberRage")}'
        context = {"meth": meth, "KEY": auth_key, "QR": QR}
        return render(request, "accounts/mfa.html", context)

    def post(self, request):
        user = self.request.user
        NewKey = AuthKey()
        NewKey.user = user
        NewKey.auth_key = request.POST.get("key")
        NewKey.enabled = True
        NewKey.save()
        return redirect(reverse("accounts:profile", kwargs={"pk": user.id}))


class LoginView(View):
    def get(self, request):
        form = LoginForm()
        return render(request, "accounts/log_in.html", {"form": form})

    def post(self, request):
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get("email")
            password = form.cleaned_data.get("password")
            provided_auth_key = form.cleaned_data.get("two_fa")
            user = authenticate(email=email, password=password)
            if user is not None:
                if hasattr(user, "mfa"):
                    totp = pyotp.TOTP(user.mfa.auth_key)
                    user_auth_key = totp.now()
                    if user_auth_key == provided_auth_key:
                        login(request, user)
                        return redirect("home")
                    else:
                        form.add_error("two_fa", "Invalid 2FA Code")
                        return render(request, "accounts/log_in.html", {'form': form})
                else:
                    form.add_error(None, "You should enable MFA first. Press \"Reset auth_key\" button below")
                    return render(request, "accounts/log_in.html", {'form': form})
            else:
                form.add_error(None, "Invalid login credentials OR user doesn't exist")
                return render(request, "accounts/log_in.html", {'form': form})
        else:
            form.add_error(None, "Invalid login credentials")
            return render(request, "accounts/log_in.html", {'form': form})


class LogoutView(outV):
    pass


class ProfileView(DetailView):
    model = User
    template_name = "accounts/profile.html"

    def get_queryset(self):
        if self.request.user.is_authenticated:
            return User.objects.filter(pk=self.request.user.id)
        else:
            return User.objects.none()