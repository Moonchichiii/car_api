from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class VehiclesConfig(AppConfig):
    """Configuration for the vehicles app."""
    
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.vehicles"
    verbose_name = _("Vehicles")
