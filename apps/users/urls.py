"""URL patterns for the users app."""

from django.urls import path

from .views import UserViewSet

app_name = "users"  # pylint: disable=invalid-name

urlpatterns = [
    path(
        "",
        UserViewSet.as_view({"get": "retrieve", "patch": "partial_update"}),
        name="profile",
    ),
    path("logout/", UserViewSet.as_view({"post": "logout"}), name="logout"),
]
