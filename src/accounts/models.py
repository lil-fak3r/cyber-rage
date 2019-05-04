from django.db import models
from django.conf import settings
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager
)
from django.core.validators import RegexValidator, MaxValueValidator
from django.utils import timezone
from django.db.models.signals import post_save
from django.dispatch import receiver

USERNAME_REGEX = "^[a-zA-Z0-9]*$"


class UserManager(BaseUserManager):
    def _create_user(
        self,
        email,
        username,
        password,
        is_staff,
        is_superuser,
        is_active,
        **extra_fields,
    ):
        if not email:
            raise ValueError("Email required.")
        if not username:
            raise ValueError("Username required.")
        if not password:
            raise ValueError("Password required.")

        user = self.model(
            email=self.normalize_email(email),
            username=username,
            is_active=True,
            is_staff=is_staff,
            is_superuser=is_superuser,
            **extra_fields,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, username, password=None, **extra_fields):
        return self._create_user(
            email, username, password, True, False, False, **extra_fields
        )

    def create_superuser(self, email, username, password, **extra_fields):
        return self._create_user(
            email, username, password, True, True, True, **extra_fields
        )


class User(AbstractBaseUser):
    email = models.EmailField(
        max_length=40,
        unique=True,
        error_messages={"unique": "A user with that email already exists."},
    )
    username = models.CharField(
        max_length=30,
        validators=[
            RegexValidator(
                regex=USERNAME_REGEX,
                message="Username may only contain letters and numbers",
                code="invalid_username",
            )
        ],
        error_messages={"unique": "A user with that username already exists."},
        unique=True,
    )
    date_joined = models.DateTimeField(default=timezone.now)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    objects = UserManager()

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_superuser


class AuthKey(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="mfa")
    auth_key = models.CharField(max_length=16)
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    enabled = models.BooleanField()

    def __str__(self):
        return f"Auth_key for [{self.user.username}]"


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    country = models.CharField(max_length=50, blank=True)
    rankStr = models.CharField(max_length=30, default="Noob")
    rankPercentage = models.PositiveSmallIntegerField(
        default=0, validators=[MaxValueValidator(100)], verbose_name="Rank %"
    )
    points = models.PositiveSmallIntegerField(default="0")

    def __str__(self):
        return f"{self.user.username} profile"


class UserChallenges(models.Model):
    class Meta:
        verbose_name = "user challenges"
        verbose_name_plural = "User challenges"

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="challenges"
    )
    general_skills_Points = models.PositiveSmallIntegerField(default=0)
    general_skills_Percentage = models.PositiveSmallIntegerField(
        default=0, verbose_name="General Skills %"
    )
    crypto_Points = models.PositiveSmallIntegerField(default=0)
    crypto_Percentage = models.PositiveSmallIntegerField(
        default=0, verbose_name="Crypto %"
    )
    stego_Points = models.PositiveSmallIntegerField(default=0)
    stego_Percentage = models.PositiveSmallIntegerField(
        default=0, verbose_name="Stego %"
    )
    binary_exploitation_Points = models.PositiveSmallIntegerField(default=0)
    binary_exploitation_Percentage = models.PositiveSmallIntegerField(
        default=0, verbose_name="Binary Exp. %"
    )
    web_exploitation_Points = models.PositiveSmallIntegerField(default=0)
    web_exploitation_Percentage = models.PositiveSmallIntegerField(
        default=0, verbose_name="Web Exp. %"
    )
    forensics_Points = models.PositiveSmallIntegerField(default=0)
    forensics_Percentage = models.PositiveSmallIntegerField(
        default=0, verbose_name="Forensics %"
    )
    reversing_Points = models.PositiveSmallIntegerField(default=0)
    reversing_Percentage = models.PositiveSmallIntegerField(
        default=0, verbose_name="Reversing %"
    )
    solved = models.PositiveSmallIntegerField(default=0)

    def __str__(self):
        return f"{self.user.username} challenges"


class Badges(models.Model):
    pass


@receiver(post_save, sender=User)
def create_profile_challenges(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
        UserChallenges.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_userprofile(sender, instance, **kwargs):
    instance.profile.save()
    instance.challenges.save()
