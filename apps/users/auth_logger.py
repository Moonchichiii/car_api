"""
Provides logging functionality for user authentication events.
"""

import json
import logging

from django.utils import timezone

logger = logging.getLogger("car_api.auth")


def log_auth_event(event_type, user=None, request=None, extra_data=None):
    """
    Log authentication-related events with structured data.

    Args:
        event_type (str): Type of event ('login', 'logout', 'register', 'login_failed', etc.)
        user (User, optional): User object if available
        request (HttpRequest, optional): Request object if available
        extra_data (dict, optional): Additional data to log
    """
    log_data = {
        "event_type": event_type,
        "timestamp": timezone.now().isoformat(),
    }

    if user:
        log_data["user"] = {
            "id": getattr(user, "id", None),
            "email": getattr(user, "email", None),
            "is_staff": getattr(user, "is_staff", None),
            "is_superuser": getattr(user, "is_superuser", None),
        }
    else:
        log_data["user"] = None

    if request:
        log_data["request"] = {
            "method": request.method,
            "path": request.path,
            "ip": get_client_ip(request),
            "user_agent": request.META.get("HTTP_USER_AGENT", "Unknown"),
        }

    if extra_data and isinstance(extra_data, dict):
        log_data["extra"] = extra_data

    log_entry = json.dumps(log_data)
    logger_kwargs = {
        "extra": {
            "user": getattr(user, "email", "anonymous"),
            "ip": get_client_ip(request) if request else "unknown",
        }
    }

    if event_type in ["login_failed", "registration_failed", "auth_error"]:
        logger.warning(log_entry, **logger_kwargs)
    elif event_type in ["password_reset", "email_changed", "suspicious_activity"]:
        logger.warning(log_entry, **logger_kwargs)
    else:
        logger.info(log_entry, **logger_kwargs)

    return log_data


def get_client_ip(request):
    """
    Get client IP address from request object.
    Handles various proxy headers.
    """
    if not request:
        return None

    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR", "unknown")
    return ip
