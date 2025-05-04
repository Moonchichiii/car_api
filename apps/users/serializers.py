"""Serializers for user registration, login, and profile management."""
import logging
from typing import Any, Dict, Optional

from allauth.account.models import EmailAddress
from dj_rest_auth.registration.serializers import RegisterSerializer
from dj_rest_auth.serializers import LoginSerializer as DefaultLoginSerializer
from django.contrib.auth import authenticate
from django.db import transaction
from django.utils import timezone
from phonenumber_field.serializerfields import PhoneNumberField
from rest_framework import serializers

from .auth_logger import log_auth_event
from .mixins import ConsentRequiredMixin, LicenseRequiredMixin
from .models import User
from .utils import create_user_consents

logger = logging.getLogger(__name__)


class CustomRegisterSerializer(
    LicenseRequiredMixin, ConsentRequiredMixin, RegisterSerializer
):
    """Register a new user with strong validation & GDPR consent logging."""

    username = None
    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)
    phone_number = PhoneNumberField(required=False, allow_null=True)
    date_of_birth = serializers.DateField(required=False, allow_null=True)

    address_line1 = serializers.CharField()
    address_line2 = serializers.CharField(required=False, allow_blank=True)
    city = serializers.CharField(required=False, allow_blank=True)
    postal_code = serializers.CharField(required=False, allow_blank=True)
    country = serializers.CharField(required=False, allow_blank=True)

    drivers_license_number = serializers.CharField(
        write_only=True, style={"input_type": "password"}
    )
    drivers_license_expiry = serializers.DateField(required=False, allow_null=True)

    accepted_terms = serializers.BooleanField(default=False)
    accepted_privacy_policy = serializers.BooleanField(default=False)
    marketing_emails = serializers.BooleanField(default=False)

    def validate_email(self, email: str) -> str:
        email = email.lower()
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email already in use")
        return email

    def validate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        data = super().validate(data)
        pw = data.get("password")
        if pw:
            from django.contrib.auth.password_validation import \
                validate_password

            validate_password(pw)
        return data

    def save(self, request) -> User:
        with transaction.atomic():
            user = super().save(request)
            for f in [
                "first_name",
                "last_name",
                "phone_number",
                "date_of_birth",
                "drivers_license_number",
                "drivers_license_expiry",
                "address_line1",
                "address_line2",
                "city",
                "postal_code",
                "country",
                "accepted_terms",
                "accepted_privacy_policy",
                "marketing_emails",
            ]:
                setattr(user, f, self.validated_data.get(f, getattr(user, f, None)))

            if user.accepted_terms or user.accepted_privacy_policy:
                user.terms_acceptance_date = timezone.now()

            # For production, set this to False and rely on allauth flow
            user.email_verified = True
            user.last_login_ip = request.META.get("REMOTE_ADDR")

            user.save()

            EmailAddress.objects.update_or_create(
                user=user,
                defaults={"email": user.email, "primary": True, "verified": True},
            )

            create_user_consents(
                user,
                {
                    "accepted_terms": user.accepted_terms,
                    "accepted_privacy_policy": user.accepted_privacy_policy,
                    "marketing_emails": user.marketing_emails,
                },
                request.META.get("REMOTE_ADDR"),
            )

        log_auth_event(
            "registration_success",
            user,
            request,
            {"consent_count": user.consents.count()},
        )
        return user


class CustomLoginSerializer(DefaultLoginSerializer):
    """Log in via email & password, record last-login IP."""

    username = None
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get("email")
        pw = attrs.get("password")
        req = self.context.get("request")

        if not (email and pw):
            raise serializers.ValidationError(
                "Email & password required", code="authorization"
            )

        user = authenticate(request=req, username=email, password=pw)
        if not user or not user.is_active:
            raise serializers.ValidationError(
                "Invalid credentials", code="authorization"
            )

        user.last_login_ip = req.META.get("REMOTE_ADDR")
        user.save(update_fields=["last_login_ip"])

        attrs["user"] = user
        log_auth_event("login_success", user, req, {})
        return attrs


class UserSerializer(serializers.ModelSerializer):
    """Read/write profile, with masked driver's license."""

    phone_number = PhoneNumberField(required=False, allow_null=True)
    masked_license = serializers.SerializerMethodField()
    current_password = serializers.CharField(write_only=True, required=False)

    class Meta:
        """Meta class for UserSerializer."""
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "phone_number",
            "date_of_birth",
            "address_line1",
            "address_line2",
            "city",
            "postal_code",
            "country",
            "masked_license",
            "drivers_license_expiry",
            "drivers_license_number",
            "accepted_terms",
            "accepted_privacy_policy",
            "marketing_emails",
            "email_verified",
            "phone_verified",
            "identity_verified",
            "terms_acceptance_date",
            "last_modified",
            "date_joined",
            "current_password",
        ]
        read_only_fields = [
            "id",
            "email_verified",
            "masked_license",
            "date_joined",
            "last_modified",
        ]
        extra_kwargs = {"drivers_license_number": {"write_only": True}}

    def get_masked_license(self, obj: User) -> Optional[str]:
        """Return the last 4 digits of the driver's license number, masked."""
        num = obj.drivers_license_number or ""
        return f"{'*'*(len(num)-4)}{num[-4:]}" if len(num) >= 4 else None

    def validate(self, attrs):
        user = self.instance
        new_email = attrs.get("email")
        pwd = attrs.pop("current_password", None)

        if new_email and new_email.lower() != user.email.lower():
            if not pwd or not user.check_password(pwd):
                raise serializers.ValidationError(
                    {"current_password": "Required/correct to change email"}
                )
            if (
                User.objects.filter(email__iexact=new_email)
                .exclude(pk=user.pk)
                .exists()
            ):
                raise serializers.ValidationError({"email": "Already in use"})
            attrs["email"] = new_email.lower()

        return super().validate(attrs)

    def update(self, instance, data):
        with transaction.atomic():
            user = super().update(instance, data)
        return user
