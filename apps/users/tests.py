"""Tests for the users app."""
import pytest
from django.utils import timezone
from rest_framework.test import APIClient
from apps.users.models import UserManager


@pytest.mark.django_db
def test_create_user_requires_email():
    """Test that creating a user requires an email."""
    manager = UserManager()
    with pytest.raises(ValueError):
        manager.create_user(email=None, password='pwd')


@pytest.mark.django_db
def test_superuser_flags():
    """Test that superuser creation sets the correct flags."""
    manager = UserManager()
    su = manager.create_superuser('admin@example.com', 'pwd')
    assert su.is_staff and su.is_superuser and su.email_verified and su.identity_verified


@pytest.mark.django_db
def test_user_is_adult_and_verified(user_factory):
    """Test the is_adult and is_verified properties."""
    u = user_factory(
        date_of_birth=timezone.now().date().replace(year=timezone.now().year-30),
        email_verified=True,
        identity_verified=True
    )
    assert u.is_adult
    assert u.is_verified


@pytest.fixture
def api_client():
    """Fixture for API client."""
    return APIClient()


@pytest.mark.django_db
def test_register_and_set_cookies(client):
    """Test user registration via API and cookie setting."""
    payload = {
        'email': 'new@example.com',
        'password': 'pass1234',
        'confirm_password': 'pass1234',
        'accepted_terms': True,
        'accepted_privacy_policy': True,
    }
    resp = client.post('/api/auth/register/', payload, format='json')
    assert resp.status_code == 201
    assert 'Set-Cookie' in resp.headers
    assert resp.data['user']['email'] == 'new@example.com'
