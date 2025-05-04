"""Django admin configuration for the users app."""

from typing import Any, Dict, Optional
from django.http import HttpRequest
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from .auth_logger import log_auth_event


class LicenseRequiredMixin:
    """Ensure driver’s license number and expiry are provided."""

    def validate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        data = super().validate(data)
        request: Optional[HttpRequest] = self.context.get("request")

        missing_number = not data.get("drivers_license_number")
        missing_expiry = not data.get("drivers_license_expiry")
        if missing_number or missing_expiry:
            errors: Dict[str, str] = {}
            if missing_number:
                errors["drivers_license_number"] = _(
                    "Driver’s license number is required."
                )
            if missing_expiry:
                errors["drivers_license_expiry"] = _(
                    "Driver’s license expiry date is required."
                )
            log_auth_event(
                "registration_failed",
                None,
                request,
                {"reason": "missing_license_info", "email": data.get("email")},
            )
            raise serializers.ValidationError(errors)
        return data


class ConsentRequiredMixin:
    """Ensure acceptance of Terms of Service and Privacy Policy."""

    def validate(self, data: Dict[str, Any]) -> Dict[str, Any]:
        data = super().validate(data)
        request: Optional[HttpRequest] = self.context.get("request")

        if not data.get("accepted_terms"):
            log_auth_event(
                "registration_failed",
                None,
                request,
                {"reason": "terms_not_accepted", "email": data.get("email")},
            )
            raise serializers.ValidationError(
                {"accepted_terms": _("You must accept the Terms of Service.")}
            )

        if not data.get("accepted_privacy_policy"):
            log_auth_event(
                "registration_failed",
                None,
                request,
                {"reason": "privacy_policy_not_accepted", "email": data.get("email")},
            )
            raise serializers.ValidationError(
                {"accepted_privacy_policy": _("You must accept the Privacy Policy.")}
            )

        return data
