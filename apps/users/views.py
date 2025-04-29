"""Views for user authentication and profile management."""

from django.conf import settings
from django.contrib.auth import authenticate

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from social_core.exceptions import AuthException
from social_django.utils import load_strategy, load_backend

from .serializers import UserSerializer, LoginSerializer


class SetAuthCookiesMixin:
    """Mixin to set authentication cookies."""
    def _set_auth_cookies(self, response, refresh):
        """Sets JWT access and refresh tokens as cookies."""
        response.set_cookie(
            key=settings.JWT_AUTH_COOKIE,
            value=str(refresh.access_token),
            httponly=settings.JWT_AUTH_COOKIE_HTTP_ONLY,
            secure=settings.JWT_AUTH_COOKIE_SECURE,
            samesite=settings.JWT_AUTH_COOKIE_SAMESITE
        )
        response.set_cookie(
            key=settings.JWT_AUTH_REFRESH_COOKIE,
            value=str(refresh),
            httponly=settings.JWT_AUTH_COOKIE_HTTP_ONLY,
            secure=settings.JWT_AUTH_COOKIE_SECURE,
            samesite=settings.JWT_AUTH_COOKIE_SAMESITE
        )


class RegisterView(SetAuthCookiesMixin, APIView):
    """Handles user registration."""
    permission_classes = [AllowAny]

    def post(self, request):
        """Creates a new user and sets auth cookies."""
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            response = Response(
                {
                    'user': UserSerializer(user).data,
                    'message': 'User created successfully'
                },
                status=status.HTTP_201_CREATED
            )
            self._set_auth_cookies(response, refresh)
            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(SetAuthCookiesMixin, APIView):
    """Handles user login with email and password."""
    permission_classes = [AllowAny]

    def post(self, request):
        """Authenticates a user and sets auth cookies."""
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = authenticate(email=email, password=password)

            if user:
                refresh = RefreshToken.for_user(user)
                response = Response({'user': UserSerializer(user).data})
                self._set_auth_cookies(response, refresh)
                return response

            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GoogleLoginView(SetAuthCookiesMixin, APIView):
    """Handles user login/registration via Google OAuth2."""
    permission_classes = [AllowAny]

    def post(self, request):
        """Authenticates a user using Google token_id and sets auth cookies."""
        token = request.data.get('token_id')

        if not token:
            return Response(
                {'error': 'Google token is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            strategy = load_strategy(request)
            # The 'google-oauth2' name corresponds to the backend name
            # defined in settings.AUTHENTICATION_BACKENDS
            backend = load_backend(strategy, 'google-oauth2', redirect_uri=None)

            # backend.do_auth expects the access_token (which is the token_id from frontend)
            user = backend.do_auth(token)
            if user:
                # Check if the user is active
                if not user.is_active:
                    return Response(
                        {'error': 'User account is disabled.'},
                        status=status.HTTP_401_UNAUTHORIZED
                    )

                refresh = RefreshToken.for_user(user)
                response = Response({'user': UserSerializer(user).data})
                self._set_auth_cookies(response, refresh)
                return response

            return Response(
                {'error': 'Authentication failed'},
                status=status.HTTP_401_UNAUTHORIZED
            )

        except AuthException as e:
            # Catch specific exceptions from python-social-auth
            return Response(
                {'error': f'Authentication failed: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            # Catch any other unexpected exceptions
            # Log this exception e for debugging purposes
            print(f"Unexpected error during Google login: {e}")
            return Response(
                {'error': 'An unexpected error occurred during authentication.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LogoutView(APIView):
    """Handles user logout."""
    permission_classes = [IsAuthenticated]

    # pylint: disable=unused-argument
    def post(self, request):
        """Logs out the user by deleting auth cookies."""
        response = Response({'message': 'Logged out successfully'})
        response.delete_cookie(settings.JWT_AUTH_COOKIE)
        response.delete_cookie(settings.JWT_AUTH_REFRESH_COOKIE)
        return response


class UserProfileView(APIView):
    """Handles retrieving and updating user profile."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Retrieves the profile of the authenticated user."""
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    def patch(self, request):
        """Updates the profile of the authenticated user."""
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
