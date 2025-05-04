"""Application configuration for the 'users' app."""

from django.apps import AppConfig


class UsersConfig(AppConfig):
    """Configuration for the users app."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.users"
    label = "users"

    def ready(self):
        import apps.users.signals  # pylint disable=unused-import
