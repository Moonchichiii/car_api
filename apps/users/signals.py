"""Signal handlers for user authentication and consent events.

This module contains signal receivers that handle various user-related events
such as login, logout, signup, email confirmation, and consent management.
"""

from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver
from allauth.account.signals import (
    email_confirmed,
    user_logged_in,
    user_logged_out,
    user_signed_up,
)

from .auth_logger import get_client_ip, log_auth_event
from .models import UserConsent

User = get_user_model()


@receiver(user_logged_in)
def on_login(_sender, request, user, **_kwargs):
    """Handle user login signal.
    
    Args:
        _sender: The sender of the signal (unused)
        request: The HTTP request object
        user: The user object
        **_kwargs: Additional keyword arguments (unused)
    """
    if request:
        user.last_login_ip = get_client_ip(request)
        user.save(update_fields=["last_login_ip"])
    log_auth_event("login", user, request)


@receiver(user_logged_out)
def on_logout(_sender, request, user, **_kwargs):
    """Handle user logout signal.
    
    Args:
        _sender: The sender of the signal (unused)
        request: The HTTP request object
        user: The user object
        **_kwargs: Additional keyword arguments (unused)
    """
    log_auth_event("logout", user, request)


@receiver(user_signed_up)
def on_signup(_sender, request, user, **_kwargs):
    """Handle user signup signal.
    
    Args:
        _sender: The sender of the signal (unused)
        request: The HTTP request object
        user: The user object
        **_kwargs: Additional keyword arguments (unused)
    """
    method = "api" if request.path.startswith("/api/auth/registration") else "form"
    log_auth_event("signup", user, request, {"via": method})
    if request:
        user.last_login_ip = get_client_ip(request)
        user.save(update_fields=["last_login_ip"])


@receiver(email_confirmed)
def on_email_confirmed(_sender, request, email_address, **_kwargs):
    """Handle email confirmation signal.
    
    Args:
        _sender: The sender of the signal (unused)
        request: The HTTP request object
        email_address: The email address that was confirmed
        **_kwargs: Additional keyword arguments (unused)
    """
    user = email_address.user
    log_auth_event("email_confirmed", user, request)


@receiver(post_save, sender=UserConsent)
def on_consent(_sender, instance, created, **_kwargs):
    """Handle UserConsent save signal.
    
    Args:
        _sender: The sender of the signal (unused)
        instance: The UserConsent instance
        created: Boolean indicating if this was a new instance
        **_kwargs: Additional keyword arguments (unused)
    """
    action = "consent_created" if created else "consent_updated"
    log_auth_event(
        action,
        instance.user,
        None,
        {"type": instance.consent_type, "given": instance.given},
    )
