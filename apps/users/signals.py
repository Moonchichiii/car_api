"""Signals for user authentication events."""
from allauth.account.signals import (email_confirmed, user_logged_in,
                                     user_logged_out, user_signed_up)
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver

from .auth_logger import get_client_ip, log_auth_event
from .models import UserConsent

User = get_user_model()


@receiver(user_logged_in)
def on_login(sender, request, user, **kwargs):
    if request:
        user.last_login_ip = get_client_ip(request)
        user.save(update_fields=["last_login_ip"])
    log_auth_event("login", user, request)


@receiver(user_logged_out)
def on_logout(sender, request, user, **kwargs):
    log_auth_event("logout", user, request)


@receiver(user_signed_up)
def on_signup(sender, request, user, **kwargs):
    method = "api" if request.path.startswith("/api/auth/registration") else "form"
    log_auth_event("signup", user, request, {"via": method})
    if request:
        user.last_login_ip = get_client_ip(request)
        user.save(update_fields=["last_login_ip"])


@receiver(email_confirmed)
def on_email_confirmed(sender, request, email_address, **kwargs):
    user = email_address.user
    log_auth_event("email_confirmed", user, request)


@receiver(post_save, sender=UserConsent)
def on_consent(sender, instance, created, **kwargs):
    action = "consent_created" if created else "consent_updated"
    log_auth_event(
        action,
        instance.user,
        None,
        {"type": instance.consent_type, "given": instance.given},
    )
