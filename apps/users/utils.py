"""Django admin configuration for the users app."""

import logging
from typing import Dict, List, Optional
from django.core.validators import validate_ipv46_address
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone
from django.db import DatabaseError
from .models import UserConsent

logger = logging.getLogger(__name__)


def create_user_consents(
    user: "User", consent_data: Dict[str, bool], ip_address: Optional[str] = None
) -> List[UserConsent]:
    """Bulk-create GDPR consents for a user."""
    mapping = {
        "accepted_terms": "terms",
        "accepted_privacy_policy": "privacy",
        "marketing_emails": "marketing",
    }
    now = timezone.now()
    try:
        if ip_address:
            validate_ipv46_address(ip_address)
        valid_ip = ip_address
    except DjangoValidationError:
        valid_ip = None

    consents: List[UserConsent] = []
    for field, ctype in mapping.items():
        if consent_data.get(field):
            consents.append(
                UserConsent(
                    user=user,
                    consent_type=ctype,
                    given=True,
                    ip_address=valid_ip,
                    timestamp=now,
                )
            )
    if not consents:
        return []
    try:
        UserConsent.objects.bulk_create(consents)
    except DatabaseError as e:
        logger.error("Failed to bulk-create consents for user %s: %s", user.id, e)
        return []
    return consents
