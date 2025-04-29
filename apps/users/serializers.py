"""Serializers for the users app."""
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from phonenumber_field.serializerfields import PhoneNumberField
from apps.users.models import UserConsent

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """Serializer for the User model with enhanced validation."""
    phone_number = PhoneNumberField(required=False)
    confirm_password = serializers.CharField(write_only=True, required=False)
    accepted_terms = serializers.BooleanField(required=False)
    accepted_privacy_policy = serializers.BooleanField(required=False)

    class Meta:
        """Meta class for UserSerializer."""
        model = User
        fields = (
            'id', 'email', 'first_name', 'last_name', 'password', 'confirm_password',
            'phone_number', 'date_of_birth', 'address_line1', 'address_line2',
            'city', 'postal_code', 'country', 'drivers_license_number',
            'drivers_license_expiry', 'accepted_terms', 'accepted_privacy_policy',
            'marketing_emails', 'email_verified', 'phone_verified', 'identity_verified'
        )
        extra_kwargs = {
            'password': {'write_only': True},
            'email_verified': {'read_only': True},
            'phone_verified': {'read_only': True},
            'identity_verified': {'read_only': True},
        }

    def validate_date_of_birth(self, value):
        """Validate user is at least 18 years old."""
        if not value:
            return value

        current_date = timezone.now().date()
        age = current_date.year - value.year

        # Adjust age if birthday hasn't occurred yet this year
        if (current_date.month, current_date.day) < (value.month, value.day):
            age -= 1

        if age < 18:
            raise serializers.ValidationError(_("You must be at least 18 years old to register."))
        return value

    def validate(self, attrs):
        """Validate password confirmation and terms acceptance for new users."""
        # Only validate these fields during creation, not updates
        if self.instance is None:  # This is a create operation
            # Require password confirmation
            if 'confirm_password' in attrs:
                if attrs['password'] != attrs.pop('confirm_password'):
                    raise serializers.ValidationError(
                        {"confirm_password": _("Passwords don't match.")}
                    )

            # Require terms acceptance
            if not attrs.get('accepted_terms', False):
                raise serializers.ValidationError(
                    {"accepted_terms": _("You must accept the Terms of Service.")}
                )

            # Require privacy policy acceptance
            if not attrs.get('accepted_privacy_policy', False):
                raise serializers.ValidationError(
                    {"accepted_privacy_policy": _("You must accept the Privacy Policy.")}
                )

        return attrs

    def create(self, validated_data):
        """Create and return a new user with required fields."""
        # Set acceptance timestamp
        if validated_data.get('accepted_terms') or validated_data.get('accepted_privacy_policy'):
            validated_data['terms_acceptance_date'] = timezone.now()

        # Create user
        user = User.objects.create_user(
            email=validated_data.pop('email'),
            password=validated_data.pop('password'),
            **validated_data
        )

        # Create consent records
        request = self.context.get('request')
        if request and hasattr(request, 'META'):
            ip_address = self._get_client_ip(request)
            self._create_consent_records(user, ip_address)

        return user

    def update(self, instance, validated_data):
        """Update user with special handling for password changes."""
        # Handle password updates
        password = validated_data.pop('password', None)
        if password:
            instance.set_password(password)

        # Track GDPR consent changes
        self._handle_consent_updates(instance, validated_data)

        # Update other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        return instance

    def _get_client_ip(self, request):
        """Extract client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')

    def _create_consent_records(self, user, ip_address):
        """Create consent records for a new user."""
        consents = []
        if user.accepted_terms:
            consents.append(('terms', True))
        if user.accepted_privacy_policy:
            consents.append(('privacy', True))
        if user.marketing_emails:
            consents.append(('marketing', True))

        for consent_type, given in consents:
            UserConsent.objects.create(  # pylint: disable=no-member
                user=user,
                consent_type=consent_type,
                given=given,
                ip_address=ip_address
            )

    def _handle_consent_updates(self, instance, validated_data):
        """Handle updates to user consent fields."""
        request = self.context.get('request')
        ip_address = None
        if request and hasattr(request, 'META'):
            ip_address = self._get_client_ip(request)

        # Check for terms acceptance
        terms_changed = (
            'accepted_terms' in validated_data and 
            validated_data['accepted_terms'] != instance.accepted_terms
        )
        if terms_changed:
            validated_data['terms_acceptance_date'] = timezone.now()
            UserConsent.objects.create(  # pylint: disable=no-member
                user=instance,
                consent_type='terms',
                given=validated_data['accepted_terms'],
                ip_address=ip_address
            )

        # Check for privacy policy acceptance
        privacy_changed = (
            'accepted_privacy_policy' in validated_data and 
            validated_data['accepted_privacy_policy'] != instance.accepted_privacy_policy
        )
        if privacy_changed:
            if not instance.terms_acceptance_date and validated_data['accepted_privacy_policy']:
                validated_data['terms_acceptance_date'] = timezone.now()
            UserConsent.objects.create(  # pylint: disable=no-member
                user=instance,
                consent_type='privacy',
                given=validated_data['accepted_privacy_policy'],
                ip_address=ip_address
            )

        # Check for marketing preferences
        marketing_changed = (
            'marketing_emails' in validated_data and 
            validated_data['marketing_emails'] != instance.marketing_emails
        )
        if marketing_changed:
            UserConsent.objects.create(  # pylint: disable=no-member
                user=instance,
                consent_type='marketing',
                given=validated_data['marketing_emails'],
                ip_address=ip_address
            )


class LoginSerializer(serializers.Serializer):
    """Serializer for user login."""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def create(self, validated_data):
        """Create method not used for login."""
        raise NotImplementedError("LoginSerializer does not support create operations")

    def update(self, instance, validated_data):
        """Update method not used for login."""
        raise NotImplementedError("LoginSerializer does not support update operations")
