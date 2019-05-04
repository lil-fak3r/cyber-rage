from django.contrib import admin
from django.urls import path, include

from . import views


urlpatterns = [
    path('super_u/', admin.site.urls),
    path('', views.HomeView.as_view(), name='home'),
    path('accounts/', include('accounts.urls', namespace='accounts'))
]
