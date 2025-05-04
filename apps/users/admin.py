"""Admin configuration for the custom User model and related models."""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _

from .models import User, UserConsent, VerificationToken


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin configuration for the custom User model."""

    # Fields to display
    list_display = (
        "email",
        "first_name",
        "last_name",
        "phone_number",
        "date_of_birth",
        "is_staff",
        "is_active",
        "email_verified",
        "phone_verified",
    )

    # Search Fields
    search_fields = ("email", "first_name", "last_name")

    # Filters
    list_filter = (
        "is_staff",
        "is_superuser",
        "is_active",
        "email_verified",
        "phone_verified",
        "identity_verified",
        "date_joined",
    )
    ordering = ("email",)

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (
            _("Personal info"),
            {
                "fields": (
                    "first_name",
                    "last_name",
                    "date_of_birth",
                    "phone_number",
                )
            },
        ),
        (
            _("Address"),
            {
                "fields": (
                    "address_line1",
                    "address_line2",
                    "city",
                    "postal_code",
                    "country",
                )
            },
        ),
        (
            _("Driver's license"),
            {
                "fields": (
                    "drivers_license_number",
                    "drivers_license_expiry",
                    "has_valid_license",
                )
            },
        ),
        (
            _("Verification"),
            {
                "fields": (
                    "email_verified",
                    "phone_verified",
                    "identity_verified",
                    "id_document_type",
                    "id_verification_timestamp",
                )
            },
        ),
        (
            _("GDPR & Consent"),
            {
                "fields": (
                    "accepted_terms",
                    "accepted_privacy_policy",
                    "terms_acceptance_date",
                    "marketing_emails",
                    "account_deletion_requested",
                    "anonymized",
                )
            },
        ),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        (_("Important dates"), {"fields": ("last_login", "date_joined")}),
    )

    # The fieldsets for the add user form
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "password1",
                    "password2",
                    "first_name",
                    "last_name",
                    "is_staff",
                    "is_active",
                ),
            },
        ),
    )

    readonly_fields = (
        "date_joined",
        "last_login",
        "has_valid_license",
        "terms_acceptance_date",
        "id_document_type",
        "id_verification_timestamp",
    )

    filter_horizontal = ("groups", "user_permissions")


@admin.register(VerificationToken)
class VerificationTokenAdmin(admin.ModelAdmin):
    """Admin for verification tokens."""

    list_display = ("user", "type", "created_at", "expires_at", "used", "is_valid")
    list_filter = ("type", "used")
    search_fields = ("user__email", "token")
    readonly_fields = ("created_at", "expires_at", "token")


@admin.register(UserConsent)
class UserConsentAdmin(admin.ModelAdmin):
    """Admin for user consent records."""

    list_display = ("user", "consent_type", "given", "timestamp", "ip_address")
    list_filter = ("consent_type", "given")
    search_fields = ("user__email",)
    readonly_fields = ("timestamp",)
