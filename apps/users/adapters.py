"""
Custom adapters for django-allauth.
"""

from allauth.account.adapter import DefaultAccountAdapter
from django.contrib.auth import get_user_model
from django.utils import timezone


class CustomAccountAdapter(DefaultAccountAdapter):
    """
    Custom adapter for allauth to handle email-based user registration
    with custom fields.
    """

    def populate_username(self, request, user):
        """
        Prevent Allauth from trying to generate a username;
        just use the email as the username.
        """
        user.username = user.email

    def save_user(self, request, user, form, commit=True):
        """Override to save all custom fields."""
        # Getting data from the form
        data = form.cleaned_data

        # Core field provided by Django
        user.email = data.get("email")

        # Custom fields
        user.first_name = data.get("first_name", "")
        user.last_name = data.get("last_name", "")
        user.phone_number = data.get("phone_number")
        user.date_of_birth = data.get("date_of_birth")
        user.drivers_license_number = data.get("drivers_license_number", "")
        user.drivers_license_expiry = data.get("drivers_license_expiry")

        # Address fields
        user.address_line1 = data.get("address_line1", "")
        user.address_line2 = data.get("address_line2", "")
        user.city = data.get("city", "")
        user.postal_code = data.get("postal_code", "")
        user.country = data.get("country", "")

        # GDPR fields
        user.accepted_terms = data.get("accepted_terms", False)
        user.accepted_privacy_policy = data.get("accepted_privacy_policy", False)
        user.marketing_emails = data.get("marketing_emails", False)

        # Set terms acceptance date if terms were accepted
        if user.accepted_terms or user.accepted_privacy_policy:
            user.terms_acceptance_date = timezone.now()

        # Set password
        if "password1" in data:
            user.set_password(data["password1"])

        # Save the user
        if commit:
            user.save()
        return user

    def get_phone(self, user):
        """Return the user's phone number."""

        return getattr(user, "phone_number", None)

    def get_user_by_phone(self, phone_number):
        """Return the user associated with the phone number."""

        User = self.get_user_model()
        try:
            return User.objects.get(phone_number=phone_number)
        except User.DoesNotExist:
            return None

    def send_verification_code_sms(self, request, phone_number, code):
        """Send verification code via SMS."""

        raise NotImplementedError("SMS sending is not implemented.")

    def set_phone(self, user, phone_number):
        """Set the user's phone number."""

        user.phone_number = phone_number

    def set_phone_verified(self, user, verified):
        """Set the phone verification status."""

        raise NotImplementedError(
            "Phone verification status setting is not implemented."
        )

    def get_user_model(self):
        """Helper to get the user model."""
        return get_user_model()
