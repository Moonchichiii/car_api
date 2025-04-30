"""Django admin configuration for the users app."""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _

from .models import VerificationToken, UserConsent

User = get_user_model()


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin configuration for the custom ``User`` model."""


    # List settings

    list_display = (
        "email",
        "first_name",
        "last_name",
        "is_staff",
        "is_active",
        "email_verified",
        "phone_verified",
    )
    list_filter = (
        "is_staff",
        "is_superuser",
        "is_active",
        "email_verified",
        "phone_verified",
        "groups",
    )
    search_fields = ("email", "first_name", "last_name")
    ordering = ("email",)


    # Fieldsets

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (_("Personal info"), {
            "fields": (
                "first_name",
                "last_name",
                "date_of_birth",
                "phone_number",
            )
        }),
        (_("Address"), {
            "fields": (
                "address_line1",
                "address_line2",
                "city",
                "postal_code",
                "country",
            )
        }),
        (_("Driver's licence"), {
            "fields": (
                "drivers_license_number",
                "drivers_license_expiry",
                "has_valid_license",
            )
        }),
        (_("Verification"), {
            "fields": (
                "email_verified",
                "phone_verified",
                "identity_verified",
            )
        }),
        (_("Permissions"), {
            "fields": (
                "is_active",
                "is_staff",
                "is_superuser",
                "groups",
                "user_permissions",
            )
        }),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
    )

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": (
                "email",
                "password1",
                "password2",
                "is_staff",
                "is_active",
            ),
        }),
    )


    # Misc

    readonly_fields = ("date_joined", "last_login", "has_valid_license")
    filter_horizontal = ("groups", "user_permissions")



# Additional models


@admin.register(VerificationToken)
class VerificationTokenAdmin(admin.ModelAdmin):
    """Admin configuration for the ``VerificationToken`` model."""
    list_display = ("user", "type", "created_at", "expires_at", "used", "is_valid")
    list_filter = ("type", "used")
    search_fields = ("user__email", "token")
    readonly_fields = ("created_at", "expires_at", "token")


@admin.register(UserConsent)
class UserConsentAdmin(admin.ModelAdmin):
    """Admin configuration for the ``UserConsent`` model."""
    list_display = ("user", "consent_type", "given", "timestamp", "ip_address")
    list_filter = ("consent_type", "given")
    search_fields = ("user__email",)
    readonly_fields = ("timestamp",)
