"""Models for users apps."""
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from phonenumber_field.modelfields import PhoneNumberField


class UserManager(BaseUserManager):
    """Custom user manager where email is the unique identifiers for authentication."""
    def create_user(self, email, password=None, **extra_fields):
        """Create and save a User with the given email and password."""
        if not email:
            raise ValueError(_('The Email field must be set'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('email_verified', True)
        extra_fields.setdefault('identity_verified', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """Custom user model with enhanced security and GDPR compliance."""
    # Basic Information
    email = models.EmailField(_('email address'), unique=True)
    first_name = models.CharField(_('first name'), max_length=30, blank=True)
    last_name = models.CharField(_('last name'), max_length=30, blank=True)

    # Contact Information
    phone_number = PhoneNumberField(
        _('phone number'),
        blank=True,
        help_text=_("International format: +123456789")
    )
    phone_verified = models.BooleanField(default=False)

    # Address Information (important for rental agreements)
    address_line1 = models.CharField(_('address line 1'), max_length=100, blank=True)
    address_line2 = models.CharField(_('address line 2'), max_length=100, blank=True)
    city = models.CharField(_('city'), max_length=50, blank=True)
    postal_code = models.CharField(_('postal code'), max_length=20, blank=True)
    country = models.CharField(_('country'), max_length=50, blank=True)

    # Identity and Verification
    date_of_birth = models.DateField(_('date of birth'), null=True, blank=True)
    drivers_license_number = models.CharField(
        _('drivers license number'), max_length=50, blank=True
    )
    drivers_license_expiry = models.DateField(_('drivers license expiry'), null=True, blank=True)
    identity_verified = models.BooleanField(default=False)

    # National ID handling with GDPR compliance
    id_document_type = models.CharField(
        _('ID document type'),
        max_length=20,
        blank=True,
        choices=[
            ('passport', _('Passport')),
            ('national_id', _('National ID')),
            ('drivers_license', _('Driver\'s License'))
        ]
    )
    id_verification_timestamp = models.DateTimeField(null=True, blank=True)

    # Django User flags
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    email_verified = models.BooleanField(default=False)
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    # GDPR and Terms
    accepted_terms = models.BooleanField(default=False)
    accepted_privacy_policy = models.BooleanField(default=False)
    terms_acceptance_date = models.DateTimeField(null=True, blank=True)

    # Account Deletion (GDPR compliance)
    account_deletion_requested = models.DateTimeField(null=True, blank=True)
    anonymized = models.BooleanField(default=False)

    # Marketing Preferences (GDPR compliance)
    marketing_emails = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    class Meta:
        """Meta options for the User model."""
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def __str__(self):
        """Return string representation of the user."""
        return str(self.email)

    def get_full_name(self):
        """Return the full name for the user."""
        return f"{self.first_name} {self.last_name}".strip()

    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name

    @property
    def is_verified(self):
        """User has both email and identity verified."""
        return self.email_verified and self.identity_verified

    @property
    def is_adult(self):
        """Check if user is at least 18 years old."""
        if not self.date_of_birth:
            return False
        # Convert date_of_birth to Python date object to access its attributes
        dob = self.date_of_birth
        current_date = timezone.now().date()
        # Calculate age
        age = current_date.year - dob.year  # pylint: disable=no-member
        # Adjust age if birthday hasn't occurred yet this year
        if (current_date.month, current_date.day) < (dob.month, dob.day):  # pylint: disable=no-member
            age -= 1
        return age >= 18

    @property
    def has_valid_license(self):
        """Check if user has a valid driver's license."""
        if not self.drivers_license_expiry:
            return False
        return self.drivers_license_expiry > timezone.now().date()


class VerificationToken(models.Model):
    """Model for storing email and phone verification tokens."""
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=64)
    type = models.CharField(
        max_length=10,
        choices=[
            ('email', _('Email')),
            ('phone', _('Phone')),
            ('reset', _('Password Reset')),
            ('delete', _('Account Deletion'))
        ]
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    class Meta:
        """Meta options for the VerificationToken model."""
        verbose_name = _('verification token')
        verbose_name_plural = _('verification tokens')

    def __str__(self):
        """Return string representation of the verification token."""
        # Fix: Use the choice dict lookup manually instead of get_type_display
        # pylint: disable=no-member
        type_display = dict(self._meta.get_field('type').choices).get(self.type, self.type)
        return f"{type_display} token for {self.user}"

    @property
    def is_valid(self):
        """Check if token is valid (not used and not expired)."""
        return not self.used and self.expires_at > timezone.now()


class UserConsent(models.Model):
    """Track GDPR consent changes over time for audit purposes."""
    CONSENT_CHOICES = [
        ('terms', _('Terms and Conditions')),
        ('privacy', _('Privacy Policy')),
        ('marketing', _('Marketing Emails')),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='consents')
    consent_type = models.CharField(
        _('consent type'),
        max_length=30,
        choices=CONSENT_CHOICES
    )
    given = models.BooleanField(_('consent given'))
    timestamp = models.DateTimeField(_('timestamp'), auto_now_add=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)

    class Meta:
        """Meta options for the UserConsent model."""
        verbose_name = _('user consent')
        verbose_name_plural = _('user consents')
        ordering = ['-timestamp']

    def __str__(self):
        """Return string representation of the user consent."""
        status = _("granted") if self.given else _("revoked")
        # Fix: Use the choice dict lookup manually instead of get_consent_type_display
        consent_type_display = dict(self.CONSENT_CHOICES).get(self.consent_type, self.consent_type)
        return f"{self.user} {status} {consent_type_display} consent on {self.timestamp}"
