from django.urls import path
from django.views.generic import TemplateView

from . import views

app_name = "accounts"
urlpatterns = [
    path("sign_up/", views.SignupView.as_view(), name="sign_up"),
    path(
        "activate/<str:uidb64>/<str:token>/", views.SignupView.activate, name="activate"
    ),
    path("log_in/", views.LoginView.as_view(), name="log_in"),
    path("log_out/", views.LogoutView.as_view(), name="log_out"),
    path("mfa/", views.MFA.as_view(), name="mfa"),
    path("profile/<int:pk>", views.ProfileView.as_view(), name="profile"),
]
