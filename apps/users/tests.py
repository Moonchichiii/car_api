# pylint: disable=missing-module-docstring,missing-function-docstring,missing-class-docstring,unused-import,unused-argument,redefined-outer-name,line-too-long,multiple-statements,C0301,C0115,C0116,W0621,W0613,W0201,E1101,W0719
import pytest
from django.utils import timezone
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from social_core.exceptions import AuthFailed, AuthCanceled, AuthUnknownError, AuthException

import apps.users.views as user_views
from apps.users.models import VerificationToken, UserConsent
from apps.users.serializers import UserSerializer, LoginSerializer

User = get_user_model()

@pytest.mark.django_db
def test_create_user_requires_email():
    with pytest.raises(ValueError):
        User.objects.create_user(email=None, password="pwd")

@pytest.mark.django_db
def test_create_superuser_flags():
    su = User.objects.create_superuser("admin@example.com", "pwd")
    assert su.is_staff
    assert su.is_superuser
    assert su.email_verified
    assert su.identity_verified

@pytest.mark.django_db
def test_create_superuser_invalid_flags():
    with pytest.raises(ValueError):
        User.objects.create_superuser("a@b.com", "pwd", is_staff=False)
    with pytest.raises(ValueError):
        User.objects.create_superuser("a@b.com", "pwd", is_superuser=False)

@pytest.mark.django_db
def test_str_and_name_methods(user_factory):
    u = user_factory(first_name="Foo", last_name="Bar")
    assert str(u) == u.email
    assert u.get_full_name() == "Foo Bar"
    assert u.get_short_name() == "Foo"

@pytest.mark.django_db
def test_is_adult_and_edge_birthday(user_factory):
    today = timezone.now().date()
    adult = today.replace(year=today.year - 30)
    minor = today.replace(year=today.year - 10)
    edge = today.replace(year=today.year - 18)

    assert user_factory(date_of_birth=adult).is_adult
    assert not user_factory(date_of_birth=minor).is_adult
    assert user_factory(date_of_birth=edge).is_adult

@pytest.mark.django_db
def test_is_verified_property(user_factory):
    assert user_factory(email_verified=True, identity_verified=True).is_verified
    assert not user_factory(email_verified=False, identity_verified=True).is_verified
    assert not user_factory(email_verified=True, identity_verified=False).is_verified

@pytest.mark.django_db
def test_has_valid_license_property(user_factory):
    assert user_factory().has_valid_license
    expired = timezone.now().date() - timezone.timedelta(days=1)
    assert not user_factory(drivers_license_expiry=expired).has_valid_license
    assert not user_factory(drivers_license_expiry=None).has_valid_license

@pytest.mark.django_db
def test_verification_token_str_and_is_valid(user_factory):
    user = user_factory()
    token = VerificationToken.objects.create(
        user=user,
        token='abc',
        type='email',
        expires_at=timezone.now() + timezone.timedelta(hours=1)
    )
    assert 'Email token for' in str(token)
    assert token.is_valid
    # expired
    token.expires_at = timezone.now() - timezone.timedelta(hours=1)
    token.used = True
    token.save()
    assert not token.is_valid

@pytest.mark.django_db
def test_user_consent_str_and_ordering(user_factory):
    user = user_factory()
    consent = UserConsent.objects.create(user=user, consent_type='terms', given=False)
    assert 'revoked Terms and Conditions' in str(consent)

@pytest.mark.django_db
def test_user_serializer_create_valid():
    payload = {
        "email": "new@example.com",
        "password": "pass1234",
        "confirm_password": "pass1234",
        "accepted_terms": True,
        "accepted_privacy_policy": True,
        "marketing_emails": False
    }
    ser = UserSerializer(data=payload)
    assert ser.is_valid(), ser.errors
    user = ser.save()
    assert user.email == "new@example.com"
    assert user.accepted_terms and user.accepted_privacy_policy

@pytest.mark.django_db
def test_user_serializer_password_mismatch():
    payload = {"email": "x@example.com", "password": "a", "confirm_password": "b", "accepted_terms": True, "accepted_privacy_policy": True}
    ser = UserSerializer(data=payload)
    with pytest.raises(ValidationError):
        ser.is_valid(raise_exception=True)
    assert "confirm_password" in ser.errors

@pytest.mark.django_db
def test_user_serializer_missing_terms_or_privacy():
    base = {"email": "b@example.com", "password": "pass", "confirm_password": "pass"}
    ser = UserSerializer(data={**base, "accepted_privacy_policy": True})
    with pytest.raises(ValidationError): ser.is_valid(raise_exception=True)
    ser = UserSerializer(data={**base, "accepted_terms": True})
    with pytest.raises(ValidationError): ser.is_valid(raise_exception=True)

@pytest.mark.django_db
def test_user_serializer_underage():
    today = timezone.now().date()
    dob = today.replace(year=today.year - 17)
    payload = {"email": "u@example.com", "password": "pass1234", "confirm_password": "pass1234", "accepted_terms": True, "accepted_privacy_policy": True, "date_of_birth": dob.isoformat()}
    ser = UserSerializer(data=payload)
    with pytest.raises(ValidationError): ser.is_valid(raise_exception=True)
    assert "date_of_birth" in ser.errors

@pytest.mark.django_db
def test_user_serializer_validate_date_none_and_adult():
    ser = UserSerializer()
    # None passes through
    assert ser.validate_date_of_birth(None) is None
    # valid age
    today = timezone.now().date()
    dob = today.replace(year=today.year - 20)
    assert ser.validate_date_of_birth(dob) == dob

@pytest.mark.django_db
def test_user_serializer_create_consent_records():
    class DummyRequest: META = {"REMOTE_ADDR": "1.2.3.4"}
    payload = {"email": "c@example.com", "password": "pass1234", "confirm_password": "pass1234", "accepted_terms": True, "accepted_privacy_policy": True, "marketing_emails": True}
    ser = UserSerializer(data=payload, context={"request": DummyRequest()})
    assert ser.is_valid(), ser.errors
    user = ser.save()
    assert user.terms_acceptance_date is not None
    assert user.consents.count() == 3

@pytest.mark.django_db
def test_serializer_update_password_and_consent(user_factory):
    user = user_factory(accepted_terms=False, marketing_emails=False)
    class DummyRequest: META = {"HTTP_X_FORWARDED_FOR": "5.6.7.8"}
    # test privacy update only
    ser = UserSerializer(user, data={"accepted_privacy_policy": True}, partial=True, context={"request": DummyRequest()})
    assert ser.is_valid(), ser.errors
    updated = ser.save()
    assert updated.terms_acceptance_date is not None
    assert updated.consents.filter(consent_type="privacy", given=True).exists()
    # test marketing and password
    ser2 = UserSerializer(updated, data={"password": "new1234", "marketing_emails": True}, partial=True, context={"request": DummyRequest()})
    assert ser2.is_valid(), ser2.errors
    updated2 = ser2.save()
    assert updated2.check_password("new1234")
    assert updated2.consents.filter(consent_type="marketing", given=True).exists()

@pytest.mark.django_db
def test_login_serializer_no_create_update():
    ser = LoginSerializer(data={"email": "x@x.com", "password": "p"})
    assert ser.is_valid()
    with pytest.raises(NotImplementedError): ser.create(ser.validated_data)
    with pytest.raises(NotImplementedError): ser.update(None, {})

@pytest.fixture
def client(): return APIClient()

@pytest.fixture
def auth_client(user_factory):
    user = user_factory()
    token = RefreshToken.for_user(user)
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return c

@pytest.mark.django_db
def test_register_view_sets_cookies_and_invalid(client):
    url = reverse("users:register")
    good = {"email": "d@example.com", "password": "pass1234", "confirm_password": "pass1234", "accepted_terms": True, "accepted_privacy_policy": True}
    resp = client.post(url, good, format="json")
    assert resp.status_code == 201
    bad = {"email": "d2@example.com", "password": "p", "confirm_password": "p", "accepted_privacy_policy": True}
    resp2 = client.post(url, bad, format="json")
    assert resp2.status_code == 400
    assert "accepted_terms" in resp2.data

@pytest.mark.django_db
def test_login_view_success_and_bad_request(client, user_factory):
    user = user_factory(password="pass1234")
    url = reverse("users:login")
    resp = client.post(url, {"email": user.email, "password": "pass1234"}, format="json")
    assert resp.status_code == 200
    resp2 = client.post(url, {"email": user.email}, format="json")
    assert resp2.status_code == 400
    assert "password" in resp2.data

@pytest.mark.django_db
def test_logout_deletes_cookies(auth_client):
    resp = auth_client.post(reverse("users:logout"), format="json")
    assert resp.status_code == 200
    assert resp.cookies["access"].value == ""
    assert resp.cookies["refresh"].value == ""

@pytest.mark.django_db
def test_profile_get_and_patch(user_factory):
    user = user_factory(first_name="Old")
    client = APIClient()
    token = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    url = reverse("users:profile")
    resp = client.get(url)
    assert resp.status_code == 200
    assert resp.data["email"] == user.email
    resp2 = client.patch(url, {"first_name": "New"}, format="json")
    assert resp2.status_code == 200
    assert resp2.data["first_name"] == "New"
    user.refresh_from_db()
    assert user.first_name == "New"

@pytest.mark.django_db
def test_google_login_missing_token(client):
    url = reverse("users:google-login")
    resp = client.post(url, {}, format="json")
    assert resp.status_code == 400
    assert resp.data["error"] == "Google token is required"

@pytest.mark.django_db
def test_google_login_auth_failure(monkeypatch, client):
    url = reverse("users:google-login")
    class DummyBackend:
        def do_auth(self, token): return None
    monkeypatch.setattr(user_views, "load_strategy", lambda request: None)
    monkeypatch.setattr(user_views, "load_backend", lambda strat, name, redirect_uri=None: DummyBackend())
    resp = client.post(url, {"token_id": "fake"}, format="json")
    assert resp.status_code == 401
    assert resp.data["error"] == "Authentication failed"

@pytest.mark.django_db
@pytest.mark.parametrize("exc,status_code", [(AuthFailed,401),(AuthCanceled,401),(AuthUnknownError,401)])
def test_google_login_social_errors(monkeypatch, client, exc, status_code):
    url = reverse("users:google-login")
    class DummyBackend:
        def do_auth(self, token): raise exc("fail")
    monkeypatch.setattr(user_views, "load_strategy", lambda request: None)
    monkeypatch.setattr(user_views, "load_backend", lambda strat, name, redirect_uri=None: DummyBackend())
    resp = client.post(url, {"token_id": "fake"}, format="json")
    assert resp.status_code == status_code
    assert resp.data["error"] == "Authentication failed"

@pytest.mark.django_db
def test_google_login_inactive_user(monkeypatch, client, user_factory):
    url = reverse("users:google-login")
    inactive = user_factory(is_active=False)
    class DummyBackend:
        def do_auth(self, token): return inactive
    monkeypatch.setattr(user_views, "load_strategy", lambda request: None)
    monkeypatch.setattr(user_views, "load_backend", lambda strat, name, redirect_uri=None: DummyBackend())
    resp = client.post(url, {"token_id": "fake"}, format="json")
    assert resp.status_code == 401
    assert resp.data["error"] == "User account is disabled"

@pytest.mark.django_db
def test_google_login_auth_exception(monkeypatch, client):
    url = reverse("users:google-login")
    class DummyBackend:
        def do_auth(self, token): raise AuthException("err")
    monkeypatch.setattr(user_views, "load_strategy", lambda request: None)
    monkeypatch.setattr(user_views, "load_backend", lambda strat, name, redirect_uri=None: DummyBackend())
    resp = client.post(url, {"token_id": "fake"}, format="json")
    assert resp.status_code == 400
    assert resp.data["error"] == "Authentication failed"

@pytest.mark.django_db
def test_google_login_value_error(monkeypatch, client):
    url = reverse("users:google-login")
    class DummyBackend:
        def do_auth(self, token): raise ValueError("bad")
    monkeypatch.setattr(user_views, "load_strategy", lambda request: None)
    monkeypatch.setattr(user_views, "load_backend", lambda strat, name, redirect_uri=None: DummyBackend())
    resp = client.post(url, {"token_id": "fake"}, format="json")
    assert resp.status_code == 400
    assert resp.data["error"] == "Invalid token format"

@pytest.mark.django_db
def test_google_login_connection_error(monkeypatch, client):
    url = reverse("users:google-login")
    class DummyBackend:
        def do_auth(self, token): raise ConnectionError("no")
    monkeypatch.setattr(user_views, "load_strategy", lambda request: None)
    monkeypatch.setattr(user_views, "load_backend", lambda strat, name, redirect_uri=None: DummyBackend())
    resp = client.post(url, {"token_id": "fake"}, format="json")
    assert resp.status_code == 503
    assert resp.data["error"] == "Could not connect to authentication service"

@pytest.mark.django_db
def test_google_login_generic_exception(monkeypatch, client):
    url = reverse("users:google-login")
    class DummyBackend:
        def do_auth(self, token): raise Exception("oops")
    monkeypatch.setattr(user_views, "load_strategy", lambda request: None)
    monkeypatch.setattr(user_views, "load_backend", lambda strat, name, redirect_uri=None: DummyBackend())
    resp = client.post(url, {"token_id": "fake"}, format="json")
    assert resp.status_code == 500
    assert "unexpected" in resp.data["error"].lower()
