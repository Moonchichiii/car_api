"""URL configuration for the car_api project."""
from django.contrib import admin
from django.urls import include, path, re_path

urlpatterns = [
    path("admin/", admin.site.urls),
    # Authentication
    path("api/auth/", include("dj_rest_auth.urls")),
    path("api/auth/registration/", include("dj_rest_auth.registration.urls")),
    re_path(r"^accounts/", include("allauth.urls")),
    path("api/auth/profile/", include("apps.users.urls")),
]
