from django.contrib import admin
from .models import User
from django.contrib.auth.admin import UserAdmin


class CustomUserAdmin(UserAdmin):
    fieldsets = (
        (None, {
            'fields': (
                "username", "email", "password", "verification_otp"
            )
        }),
    )
    list_filter = ("is_admin", "is_active", "verification_otp")
    list_display = ("id", "username", "email", "created_at",
                    "updated_at", "is_admin", "is_active")


admin.site.register(User, CustomUserAdmin)
