"""Django admin configuration for the users app."""
import pytest
from pytest_factoryboy import register
from rest_framework.test import APIClient


# Factory-Boy registrations (auto-creates user_factory, token_factory …)

from tests.factories import UserFactory, TokenFactory, ConsentFactory

register(UserFactory)
register(TokenFactory)
register(ConsentFactory)



# Generic DRF clients

@pytest.fixture
def api_client():
    """Unauthenticated DRF test client."""
    return APIClient()


@pytest.fixture
def auth_api_client(user_factory):
    """
    DRF client authenticated as a fresh user created by `user_factory`.
    The factory attaches a JWT to the instance (`user.jwt`).
    """
    user = user_factory()
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {user.jwt}")
    return client
