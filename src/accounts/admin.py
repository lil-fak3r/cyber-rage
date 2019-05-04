from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin, Group
from django.contrib.auth import get_user_model

from .forms import UserAdminCreationForm, UserAdminChangeForm
from .models import AuthKey, UserProfile, UserChallenges

User = get_user_model()


class UserAdmin(BaseUserAdmin):
    form = UserAdminChangeForm
    add_form = UserAdminCreationForm

    list_display = ("username", "email", "is_superuser")
    list_filter = ("is_superuser", "is_staff", "is_active")

    fieldsets = (
        (None, {"fields": ("email", "username", "password")}),
        ("Personal info", {"fields": ()}),  #  do link to profile, challenges
        ("Permissions", {"fields": ("is_superuser", "is_staff")}),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "username", "password1", "password2"),
            },
        ),
    )
    search_fields = ("email", "username")
    ordering = ("email",)
    filter_horizontal = ()


admin.site.register(User, UserAdmin)
admin.site.unregister(Group)
admin.site.register(AuthKey)
admin.site.register(UserProfile)
admin.site.register(UserChallenges)
