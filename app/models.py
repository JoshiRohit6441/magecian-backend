from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, Group, Permission


import random


class MyUserManager(BaseUserManager):
    def create_user(self, email, username,  password=None, **extra_fields):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """
        if not email:
            raise ValueError("Users must have an email address")

        user = self.model(
            email=self.normalize_email(email),
            username=username,
            **extra_fields
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault("is_admin", True)
        return self.create_user(email, username, password, **extra_fields)


class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name="email address",
        max_length=255,
        unique=True,
    )
    username = models.CharField(max_length=250, unique=True)

    groups = models.ManyToManyField(
        Group, related_query_name="group", related_name="grops", blank=True, verbose_name="Group",)
    user_permissions = models.ManyToManyField(
        Permission, related_query_name="permission", related_name="permission", blank=True, verbose_name="Sser Permissions")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    verification_otp = models.IntegerField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    objects = MyUserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["email",]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    def generate_otp(self):
        otp = random.randint(100000, 999999)
        self.verification_otp = otp
        self.save()
        return otp

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        return self.is_admin

    def __str__(self):
        return self.username
