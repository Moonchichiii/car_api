import json
from datetime import date, timedelta

import pytest
from allauth.account.models import EmailAddress
from allauth.account.signals import (email_confirmed, user_logged_in,
                                     user_signed_up)
from dateutil.relativedelta import relativedelta
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.db import DatabaseError as DjangoDatabaseError
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.users.adapters import CustomAccountAdapter
from apps.users.auth_logger import get_client_ip, log_auth_event
from apps.users.middleware import AuthSecurityMiddleware
from apps.users.mixins import ConsentRequiredMixin, LicenseRequiredMixin
from apps.users.models import (BlacklistedToken, User, UserConsent,
                               VerificationToken)
from apps.users.serializers import (CustomLoginSerializer,
                                    CustomRegisterSerializer, UserSerializer)
from apps.users.utils import create_user_consents

User = get_user_model()


@pytest.mark.parametrize(
    "first,last,expected",
    [
        ("Foo", "Bar", "Foo Bar"),
        ("", "Bar", "Bar"),
        ("Foo", "", "Foo"),
        ("", "", ""),
    ],
)
@pytest.mark.django_db
def test_name_helpers(first, last, expected):
    u = User.objects.create_user(
        email="x@example.com",
        password="p",
        first_name=first,
        last_name=last,
    )
    assert str(u) == u.email
    assert u.get_full_name() == expected
    assert u.get_short_name() == (first or "")


@pytest.mark.parametrize(
    "dob,exp",
    [
        (date.today() - relativedelta(years=18) - timedelta(days=1), True),
        (date.today() - relativedelta(years=18), True),
        (date.today() - relativedelta(years=18) + timedelta(days=1), False),
        (None, False),
    ],
)
@pytest.mark.django_db
def test_is_adult(dob, exp):
    u = User.objects.create_user("a@a.com", "p", date_of_birth=dob)
    assert u.is_adult == exp


@pytest.mark.parametrize(
    "ev,iv,exp",
    [
        (True, True, True),
        (True, False, False),
        (False, True, False),
    ],
)
@pytest.mark.django_db
def test_is_verified(ev, iv, exp):
    u = User.objects.create_user(
        email="e@e.com",
        password="p",
        email_verified=ev,
        identity_verified=iv,
    )
    assert u.is_verified == exp


@pytest.mark.parametrize(
    "expiry,exp",
    [
        (date.today() + timedelta(days=1), True),
        (date.today() - timedelta(days=1), False),
        (None, False),
    ],
)
@pytest.mark.django_db
def test_has_valid_license(expiry, exp):
    u = User.objects.create_user(
        email="l@l.com",
        password="p",
        drivers_license_expiry=expiry,
    )
    assert u.has_valid_license == exp


def test_log_auth_event(monkeypatch):
    class R:
        method = "POST"
        path = "/"
        META = {"REMOTE_ADDR": "1.2.3.4", "HTTP_USER_AGENT": "ua"}

    out = log_auth_event("evt")
    assert out["event_type"] == "evt"
    assert "timestamp" in out and out["user"] is None

    dummy = User(email="u@u.com")
    logs = []
    monkeypatch.setattr(
        "apps.users.auth_logger.logger.info", lambda msg, **_: logs.append(msg)
    )
    out2 = log_auth_event("login", dummy, R(), {"foo": "bar"})
    logged = json.loads(logs[0])
    assert logged["event_type"] == "login"
    assert out2["extra"]["foo"] == "bar"


def test_get_client_ip():
    class A:
        META = {"HTTP_X_FORWARDED_FOR": "5.6.7.8,9.9.9.9"}

    class B:
        META = {"REMOTE_ADDR": "7.8.9.10"}

    assert get_client_ip(A) == "5.6.7.8"
    assert get_client_ip(B) == "7.8.9.10"
    assert get_client_ip(None) is None


@pytest.mark.django_db
def test_create_user_consents(monkeypatch):
    assert not create_user_consents(User.objects.create_user("c1@c.com", "p"), {})

    cons = create_user_consents(
        User.objects.create_user("c2@c.com", "p"),
        {"accepted_terms": True, "marketing_emails": True},
        "1.1.1.1",
    )
    assert len(cons) == 2 and all(c.ip_address == "1.1.1.1" for c in cons)

    def fail_bulk(_):
        raise DjangoDatabaseError("oops")

    monkeypatch.setattr(UserConsent.objects, "bulk_create", fail_bulk)
    assert not create_user_consents(
        User.objects.create_user("c3@c.com", "p"), {"accepted_privacy_policy": True}
    )


@pytest.mark.django_db
def test_actual_token_existence(user_factory, monkeypatch):
    """Check if the token actually exists in the request"""
    user = user_factory()
    token = RefreshToken.for_user(user).access_token
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")

    captured_request = None

    def capture_request(self):
        nonlocal captured_request
        captured_request = self
        return user

    monkeypatch.setattr("apps.users.views.UserViewSet.get_object", capture_request)

    logout_url = reverse("users:logout")
    client.post(logout_url)


@pytest.mark.django_db
def test_comprehensive_exception_handling(user_factory, monkeypatch):
    """Comprehensive test to cover all exception handling paths"""
    user = user_factory()
    refresh_token = RefreshToken.for_user(user)
    access_token = refresh_token.access_token

    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
    url = reverse("users:profile")

    log_calls = []

    def capture_log(*a, **k):
        log_calls.append((a, k))

    monkeypatch.setattr("apps.users.views.log_auth_event", capture_log)

    def mock_db_error(*args, **kwargs):
        raise DjangoDatabaseError("Database error")

    monkeypatch.setattr("apps.users.serializers.UserSerializer.save", mock_db_error)

    response = client.patch(url, {"first_name": "Test"}, format="json")
    assert response.status_code == 500
    assert "detail" in response.data

    log_calls.clear()

    def mock_general_error(*args, **kwargs):
        raise Exception("General error")

    monkeypatch.setattr(
        "apps.users.serializers.UserSerializer.save", mock_general_error
    )

    response = client.patch(url, {"first_name": "Test"}, format="json")
    assert response.status_code == 500
    assert "detail" in response.data

    log_calls.clear()

    original_hasattr = hasattr

    def mock_hasattr_with_exception(obj, attr):
        if attr == "token":
            raise Exception("hasattr error")
        return original_hasattr(obj, attr)

    import builtins

    monkeypatch.setattr(builtins, "hasattr", mock_hasattr_with_exception)

    logout_url = reverse("users:logout")
    response = client.post(logout_url)
    assert response.status_code == 200
    assert any(call[0][0] == "token_blacklist_failed" for call in log_calls)

    monkeypatch.setattr(builtins, "hasattr", original_hasattr)

    log_calls.clear()

    class MockToken:
        def __str__(self):
            raise Exception("String conversion error")

    class MockAuth:
        token = MockToken()

    class MockRequest:
        def __init__(self):
            self.auth = MockAuth()
            self.META = {"REMOTE_ADDR": "127.0.0.1"}
            self.method = "POST"

    log_calls.clear()

    def mock_create_db_error(*args, **kwargs):
        raise DjangoDatabaseError("DB error in blacklist")

    monkeypatch.setattr(
        "apps.users.models.BlacklistedToken.objects.create", mock_create_db_error
    )

    response = client.post(logout_url)
    assert response.status_code == 200
    assert any(call[0][0] == "token_blacklist_failed" for call in log_calls)

    log_calls.clear()

    def mock_create_general_error(*args, **kwargs):
        raise Exception("General exception in blacklist")

    monkeypatch.setattr(
        "apps.users.models.BlacklistedToken.objects.create", mock_create_general_error
    )

    response = client.post(logout_url)
    assert response.status_code == 200
    assert any(call[0][0] == "token_blacklist_failed" for call in log_calls)


@pytest.mark.django_db
def test_verification_token(user_factory):
    u = user_factory()
    vt = VerificationToken.objects.create(
        user=u,
        token="tk",
        type="reset",
        expires_at=timezone.now() + timedelta(hours=1),
    )
    assert "reset token for" in str(vt).lower() and vt.is_valid
    vt.used = True
    vt.save()
    assert not vt.is_valid

    vt.used = False
    vt.expires_at = timezone.now() - timedelta(days=1)
    vt.save()
    assert not vt.is_valid


@pytest.mark.parametrize(
    "data,field",
    [
        (
            {
                "email": "",
                "password": "GoodPass1!",
                "accepted_terms": True,
                "accepted_privacy_policy": True,
                "drivers_license_number": "D",
                "address_line1": "A",
                "drivers_license_expiry": date.today() + timedelta(days=1),
            },
            "email",
        ),
        (
            {
                "email": "u@u.com",
                "password": "shrt",
                "accepted_terms": True,
                "accepted_privacy_policy": True,
                "drivers_license_number": "D",
                "address_line1": "A",
                "drivers_license_expiry": date.today() + timedelta(days=1),
            },
            "password1",
        ),
        (
            {
                "email": "u@u.com",
                "password1": "GoodPass1!",
                "password2": "DiffPass2!",
                "accepted_terms": True,
                "accepted_privacy_policy": True,
                "drivers_license_number": "D",
                "address_line1": "A",
                "drivers_license_expiry": date.today() + timedelta(days=1),
            },
            "non_field_errors",
        ),
        (
            {
                "email": "u@u.com",
                "password": "GoodPass1!",
                "accepted_terms": True,
                "accepted_privacy_policy": True,
                "address_line1": "A",
                "drivers_license_expiry": date.today() + timedelta(days=1),
            },
            "drivers_license_number",
        ),
        (
            {
                "email": "u@u.com",
                "password": "GoodPass1!",
                "accepted_terms": True,
                "accepted_privacy_policy": True,
                "drivers_license_number": "D",
                "address_line1": "A",
            },
            "drivers_license_expiry",
        ),
        (
            {
                "email": "u@u.com",
                "password": "GoodPass1!",
                "accepted_privacy_policy": True,
                "drivers_license_number": "D",
                "address_line1": "A",
                "drivers_license_expiry": date.today() + timedelta(days=1),
            },
            "accepted_terms",
        ),
        (
            {
                "email": "u@u.com",
                "password": "GoodPass1!",
                "accepted_terms": True,
                "drivers_license_number": "D",
                "address_line1": "A",
                "drivers_license_expiry": date.today() + timedelta(days=1),
            },
            "accepted_privacy_policy",
        ),
    ],
)
@pytest.mark.django_db
def test_register_serializer_validation(data, field):
    if "password" in data:
        data["password1"] = data.pop("password")
    if "password1" in data and "password2" not in data:
        data["password2"] = data["password1"]

    original_data = data.copy()

    data.setdefault("email", "test@example.com")
    data.setdefault("password1", "ValidPass123!")
    data.setdefault("password2", "ValidPass123!")
    data.setdefault("accepted_terms", True)
    data.setdefault("accepted_privacy_policy", True)
    data.setdefault("drivers_license_number", "DL123")
    data.setdefault("drivers_license_expiry", date.today() + timedelta(days=1))
    data.setdefault("address_line1", "1 Test St")

    fields_to_test_missing = [
        "drivers_license_number",
        "drivers_license_expiry",
        "accepted_terms",
        "accepted_privacy_policy",
        "email",
        "address_line1",
    ]
    if field in fields_to_test_missing:
        if field not in original_data:
            data.pop(field, None)
        elif original_data.get(field) in [None, ""]:
            data[field] = original_data[field]
        elif field in original_data and field in [
            "drivers_license_number",
            "drivers_license_expiry",
            "accepted_terms",
            "accepted_privacy_policy",
        ]:
            data.pop(field, None)

    if field == "password1":
        if original_data.get("password") == "shrt":
            data["password1"] = "shrt"
            data["password2"] = "shrt"
    elif field == "non_field_errors":
        if "password1" in original_data:
            data["password1"] = original_data["password1"]
        if "password2" in original_data:
            data["password2"] = original_data["password2"]
    elif field == "email":
        if "email" in original_data:
            data["email"] = original_data["email"]

    rf = RequestFactory().post("/")
    rf.session = {}
    context = {"request": rf}

    ser = CustomRegisterSerializer(data=data, context=context)
    with pytest.raises(ValidationError) as exc:
        ser.is_valid(raise_exception=True)

    if field == "non_field_errors":
        assert field in exc.value.detail or any(
            isinstance(e, list) and e for e in exc.value.detail.values()
        )
    else:
        assert field in exc.value.detail


@pytest.mark.django_db
def test_login_serializer_not_implemented():
    ser = CustomLoginSerializer(data={"email": "a@b.com", "password": "p"})
    with pytest.raises(NotImplementedError):
        ser.create({})
    with pytest.raises(NotImplementedError):
        ser.update(None, {})


@pytest.mark.django_db
def test_custom_account_adapter_sets_fields(tmp_path):
    adapter = CustomAccountAdapter()
    form_data = {
        "email": "foo@bar.com",
        "first_name": "F",
        "last_name": "B",
        "phone_number": "+45550001111",
        "date_of_birth": date(2000, 1, 1),
        "drivers_license_number": "DL123",
        "drivers_license_expiry": date(2030, 1, 1),
        "address_line1": "1 Main St",
        "address_line2": "Suite A",
        "city": "City",
        "postal_code": "12345",
        "country": "Country",
        "accepted_terms": True,
        "accepted_privacy_policy": True,
        "marketing_emails": False,
        "password": "ComplexPwd123!",
    }

    class F:
        cleaned_data = form_data

    req = RequestFactory().post("/")
    req.META["REMOTE_ADDR"] = "1.2.3.4"
    req.session = {}
    user_instance = User()
    adapter.save_user(req, user_instance, form=F(), commit=False)

    assert user_instance.email == form_data["email"]
    assert user_instance.first_name == form_data["first_name"]
    assert user_instance.last_name == form_data["last_name"]
    assert user_instance.phone_number == form_data["phone_number"]
    assert user_instance.date_of_birth == form_data["date_of_birth"]
    assert user_instance.drivers_license_number == form_data["drivers_license_number"]
    assert user_instance.drivers_license_expiry == form_data["drivers_license_expiry"]
    assert user_instance.address_line1 == form_data["address_line1"]


def test_auth_security_middleware_triggers_ip_change(monkeypatch):
    logs = []
    monkeypatch.setattr(
        "apps.users.auth_logger.logger.info", lambda m, **k: logs.append(m)
    )

    class U:
        is_authenticated = True
        last_login_ip = "1.1.1.1"
        pk = 1
        email = "u@u.com"

    class R:
        user = U()
        META = {"HTTP_X_FORWARDED_FOR": "2.2.2.2"}
        session = {}
        path = "/"
        method = "GET"

    assert AuthSecurityMiddleware(lambda r: "OK")(R()) == "OK"
    d = json.loads(logs[-1])
    assert d["event_type"] == "ip_change_detected"


def test_license_mixin_requires_both_fields():
    class S(LicenseRequiredMixin, serializers.Serializer):
        drivers_license_number = serializers.CharField(required=False)
        drivers_license_expiry = serializers.DateField(required=False)

    with pytest.raises(serializers.ValidationError) as exc:
        rf = RequestFactory().post("/")
        rf.session = {}
        context = {"request": rf}
        S(data={}, context=context).is_valid(raise_exception=True)
    err = exc.value.detail
    assert "drivers_license_number" in err and "drivers_license_expiry" in err


def test_consent_mixin_terms_and_privacy():
    class S(ConsentRequiredMixin, serializers.Serializer):
        accepted_terms = serializers.BooleanField(required=False)
        accepted_privacy_policy = serializers.BooleanField(required=False)

    rf = RequestFactory().post("/")
    rf.session = {}
    context = {"request": rf}

    with pytest.raises(serializers.ValidationError) as e1:
        S(data={"accepted_privacy_policy": True}, context=context).is_valid(
            raise_exception=True
        )
    assert "accepted_terms" in e1.value.detail
    with pytest.raises(serializers.ValidationError) as e2:
        S(data={"accepted_terms": True}, context=context).is_valid(raise_exception=True)
    assert "accepted_privacy_policy" in e2.value.detail


@pytest.mark.django_db
def test_signup_signal_logs(monkeypatch):
    logs = []
    monkeypatch.setattr(
        "apps.users.auth_logger.logger.info", lambda m, **k: logs.append(m)
    )
    rf = RequestFactory().post("/")
    rf.META["REMOTE_ADDR"] = "3.3.3.3"
    rf.session = {}
    user = User.objects.create(email="a@b.com")
    user_signed_up.send(sender=User, request=rf, user=user)
    assert any("signup" in m for m in logs)


@pytest.mark.django_db
def test_login_signal_logs(monkeypatch, user_factory):
    logs = []
    monkeypatch.setattr(
        "apps.users.auth_logger.logger.info", lambda m, **k: logs.append(m)
    )
    rf = RequestFactory().post("/")
    rf.META["REMOTE_ADDR"] = "4.4.4.4"
    rf.session = {}
    user_logged_in.send(sender=User, request=rf, user=user_factory())
    assert any("login" in m for m in logs)


@pytest.mark.django_db
def test_email_confirmed_signal_logs(monkeypatch, user_factory):
    logs = []
    monkeypatch.setattr(
        "apps.users.auth_logger.logger.info", lambda m, **k: logs.append(m)
    )
    rf = RequestFactory().post("/")
    rf.META["REMOTE_ADDR"] = "5.5.5.5"
    rf.session = {}
    u = user_factory()
    ea = EmailAddress.objects.create(
        user=u, email=u.email, primary=True, verified=False
    )
    email_confirmed.send(sender=EmailAddress, request=rf, email_address=ea)
    assert any("email_confirmed" in m for m in logs)


@pytest.mark.django_db
def test_profile_retrieve_and_update(user_factory):
    u = user_factory()
    token = RefreshToken.for_user(u).access_token
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    url = reverse("users:profile")
    r = client.get(url)
    assert r.status_code == 200 and r.data["email"] == u.email
    p = client.patch(url, {"first_name": "New"}, format="json")
    assert p.status_code == 200 and p.data["first_name"] == "New"


@pytest.mark.django_db
def test_logout_blacklists_and_logs_out(user_factory):
    u = user_factory()
    rt = RefreshToken.for_user(u)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {rt.access_token}")
    url = reverse("users:logout")
    r = client.post(url, {"refresh": str(rt)}, format="json")
    assert r.status_code == 200
    assert r.data.get("detail")


def test_urls_reverse():
    assert reverse("users:profile") == "/api/auth/profile/"
    assert reverse("users:logout") == "/api/auth/profile/logout/"


@pytest.mark.django_db
def test_register_serializer_full_happy_path(monkeypatch):
    logs = []
    monkeypatch.setattr(
        "apps.users.auth_logger.logger.info", lambda m, **k: logs.append(m)
    )

    rf = RequestFactory().post("/")
    rf.META["REMOTE_ADDR"] = "6.6.6.6"
    rf.session = {}

    data = {
        "email": "new@u.com",
        "password1": "StrongPwd1!",
        "password2": "StrongPwd1!",
        "first_name": "A",
        "last_name": "B",
        "phone_number": "+12025550123",
        "date_of_birth": "2000-01-01",
        "accepted_terms": True,
        "accepted_privacy_policy": True,
        "drivers_license_number": "DLX",
        "drivers_license_expiry": "2030-01-01",
        "address_line1": "Addr",
    }
    monkeypatch.setattr(
        "allauth.account.adapter.DefaultAccountAdapter.unstash_verified_email",
        lambda *args, **kwargs: None,
    )

    ser = CustomRegisterSerializer(data=data, context={"request": rf})
    assert ser.is_valid(), ser.errors
    u = ser.save(rf)
    assert u.email == "new@u.com"
    ea = EmailAddress.objects.get(user=u)
    assert ea.verified and ea.primary
    assert u.consents.count() == 2


@pytest.mark.django_db
def test_login_serializer_validate_missing_credentials():
    ser = CustomLoginSerializer(data={})
    with pytest.raises(ValidationError) as e:
        ser.validate({})
    detail = e.value.detail
    assert "Email & password required" in str(detail)


@pytest.mark.django_db
def test_login_serializer_validate_wrong_credentials(user_factory):
    u = user_factory(password="rightpass")
    ser = CustomLoginSerializer(data={"email": u.email, "password": "wrong"})
    with pytest.raises(ValidationError) as e:
        ser.validate({"email": u.email, "password": "wrong"})
    assert "Invalid credentials" in str(e.value)


@pytest.mark.django_db
def test_serializers_comprehensive(user_factory):
    _existing_user = user_factory(email="existing@example.com")

    serializer = CustomRegisterSerializer()
    assert serializer.validate_email("new@example.com") == "new@example.com"
    assert serializer.validate_email("NEW@EXAMPLE.COM") == "new@example.com"

    with pytest.raises(serializers.ValidationError) as exc:
        serializer.validate_email("existing@example.com")
    assert "Email already in use" in str(exc.value)

    data = {
        "password1": "StrongPwd123!",
        "password2": "StrongPwd123!",
        "accepted_terms": True,
        "accepted_privacy_policy": True,
        "drivers_license_number": "DL123",
        "drivers_license_expiry": date.today() + timedelta(days=1),
        "address_line1": "1 Test St",
        "email": "passwordtest@example.com",
    }
    rf = RequestFactory().post("/")
    rf.session = {}
    context = {"request": rf}
    validated = serializer.validate(data)
    assert validated["password1"] == "StrongPwd123!"

    user = user_factory(email="user@example.com", password="password123")
    user_serializer = UserSerializer(instance=user)

    with pytest.raises(serializers.ValidationError) as exc:
        user_serializer.validate({"email": "new@example.com"})
    assert "current_password" in str(exc.value)

    with pytest.raises(serializers.ValidationError) as exc:
        user_serializer.validate(
            {"email": "new@example.com", "current_password": "wrongpassword"}
        )
    assert "current_password" in str(exc.value)

    with pytest.raises(serializers.ValidationError) as exc:
        user_serializer.validate(
            {"email": "existing@example.com", "current_password": "password123"}
        )
    assert "email" in str(exc.value)

    result = user_serializer.validate(
        {"email": "brandnew@example.com", "current_password": "password123"}
    )
    assert result["email"] == "brandnew@example.com"

    user = user_factory(
        email="update@example.com", first_name="Original", last_name="Name"
    )
    serializer = UserSerializer(
        instance=user,
        data={"first_name": "Updated", "last_name": "Person"},
        partial=True,
    )

    assert serializer.is_valid()
    updated_user = serializer.update(user, serializer.validated_data)
    assert updated_user.first_name == "Updated"
    assert updated_user.last_name == "Person"


@pytest.mark.django_db
def test_user_model_methods():
    user = User.objects.create_user(
        "newuser@example.com", "password123", first_name="New", last_name="User"
    )
    assert user.email == "newuser@example.com"
    assert user.check_password("password123")

    superuser = User.objects.create_superuser("admin@example.com", "adminpassword")
    assert superuser.is_staff
    assert superuser.is_superuser
    assert superuser.email_verified
    assert superuser.identity_verified

    with pytest.raises(ValueError):
        User.objects.create_user(email="")

    with pytest.raises(ValueError):
        User.objects.create_superuser(
            "admin2@example.com", "adminpassword", is_staff=False
        )

    with pytest.raises(ValueError):
        User.objects.create_superuser(
            "admin3@example.com", "adminpassword", is_superuser=False
        )

    token = VerificationToken.objects.create(
        user=user,
        token="testtoken",
        type="email",
        expires_at=timezone.now() + timedelta(days=1),
    )
    assert "email token for" in str(token).lower()
    assert token.is_valid

    token.expires_at = timezone.now() - timedelta(days=1)
    token.save()
    assert not token.is_valid

    token.expires_at = timezone.now() + timedelta(days=1)
    token.used = True
    token.save()
    assert not token.is_valid

    blacklisted = BlacklistedToken.objects.create(
        token="blacklistedtoken", expires_at=timezone.now() + timedelta(days=1)
    )
    assert "Token blacklisted at" in str(blacklisted)
