"""User profile and authentication API views."""

from django.contrib.auth import get_user_model, logout
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.translation import gettext_lazy as _
from django.db import DatabaseError

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle

from .serializers import UserSerializer
from .auth_logger import log_auth_event
from .models import BlacklistedToken

User = get_user_model()


class ProfileRateThrottle(UserRateThrottle):
    """Rate limiting for profile operations."""

    rate = "10/minute"


@method_decorator(ensure_csrf_cookie, name="dispatch")
class UserViewSet(viewsets.GenericViewSet):
    """ViewSet for user profile operations."""

    permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer
    throttle_classes = [ProfileRateThrottle]

    def get_object(self):
        """Get the authenticated user."""
        return self.request.user

    def retrieve(self, request: Request) -> Response:
        """Retrieve the currently authenticated user's profile."""
        user = self.get_object()
        log_auth_event("profile_access", user, request)

        serializer = self.get_serializer(user)
        return Response(serializer.data)

    def partial_update(self, request: Request) -> Response:
        """Update the currently authenticated user's profile."""
        user = self.get_object()
        log_auth_event("profile_update_attempt", user, request)

        serializer = self.get_serializer(
            instance=user, data=request.data, partial=True, context={"request": request}
        )

        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()

            log_auth_event("profile_update_success", user, request)
            return Response(serializer.data)

        except ValidationError as e:
            error_details = e.detail
            log_auth_event(
                "profile_update_failed", user, request, {"errors": error_details}
            )
            return Response(error_details, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError as e:
            log_auth_event(
                "profile_update_failed",
                user,
                request,
                {"errors": f"Database error: {str(e)}"},
            )
            return Response(
                {"detail": "An unexpected error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        except Exception as e:  # pylint: disable=broad-exception-caught
            log_auth_event("profile_update_failed", user, request, {"errors": str(e)})
            return Response(
                {"detail": "An unexpected error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=False, methods=["post"])
    def logout(self, request: Request) -> Response:
        """Log out the current user and blacklist the token."""
        user = self.get_object()

        token = None
        auth_exists = hasattr(request, "auth")
        if auth_exists:
            try:
                has_token = hasattr(request.auth, "token")
            except Exception:
                log_auth_event("token_blacklist_failed", user, request)
                has_token = False

            if has_token:
                try:
                    token = str(request.auth.token)
                except Exception:
                    log_auth_event("token_blacklist_failed", user, request)
                    token = None

        if token:
            try:
                BlacklistedToken.objects.create(token=token)
            except Exception:
                log_auth_event("token_blacklist_failed", user, request)

        log_auth_event("logout", user, request)
        logout(request)
        return Response(
            {"detail": _("Successfully logged out.")}, status=status.HTTP_200_OK
        )
