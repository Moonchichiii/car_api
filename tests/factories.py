# pylint: disable=missing-module-docstring,missing-function-docstring,missing-class-docstring,unused-import,unused-argument,redefined-outer-name,line-too-long,multiple-statements,C0301,C0115,C0116,W0621,W0613,W0201,E1101,W0719,R0903

"""
Factory-Boy factories shared by all apps.
"""
import factory
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from apps.users.models import User, UserConsent, VerificationToken


class UserFactory(factory.django.DjangoModelFactory):
    """Factory for User — zero side-effects, no circular imports."""

    class Meta:
        model = User
        # no django_get_or_create so FactoryBoy will always INSERT,
        # avoiding get_or_create() and its field-validation path.

    email = factory.Sequence(lambda n: f"user{n}@example.com")
    _password = "pass1234"
    password = factory.PostGenerationMethodCall("set_password", _password)

    date_of_birth = factory.LazyFunction(
        lambda: timezone.now().date().replace(year=timezone.now().year - 20)
    )
    drivers_license_expiry = factory.LazyFunction(
        lambda: timezone.now().date().replace(year=timezone.now().year + 1)
    )
    email_verified = True
    identity_verified = True

    @factory.post_generation
    def attach_jwt(self, create, extracted, **kwargs):
        """
        After the user is saved, attach a JWT token as a plain attribute.
        """
        if create:
            # pylint: disable=attribute-defined-outside-init
            self.jwt = str(RefreshToken.for_user(self).access_token)


class TokenFactory(factory.django.DjangoModelFactory):
    """Factory for VerificationToken."""

    class Meta:
        model = VerificationToken

    user = factory.SubFactory(UserFactory)
    token = factory.Faker("uuid4")
    type = "email"
    created_at = factory.LazyFunction(timezone.now)
    expires_at = factory.LazyFunction(
        lambda: timezone.now() + timezone.timedelta(hours=1)
    )


class ConsentFactory(factory.django.DjangoModelFactory):
    """Factory for UserConsent."""

    class Meta:
        model = UserConsent

    user = factory.SubFactory(UserFactory)
    consent_type = "terms"
    given = True
    ip_address = "127.0.0.1"
