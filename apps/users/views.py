from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.contrib.auth import authenticate
from .serializers import UserSerializer, LoginSerializer
from social_django.utils import load_strategy, load_backend
from social_core.backends.oauth import BaseOAuth2


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
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
    
    def _set_auth_cookies(self, response, refresh):
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


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
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
    
    def _set_auth_cookies(self, response, refresh):
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


class GoogleLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get('token_id')
        
        if not token:
            return Response(
                {'error': 'Google token is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            strategy = load_strategy(request)
            backend = load_backend(strategy, 'google-oauth2', redirect_uri=None)
            
            user = backend.do_auth(token)
            if user:
                refresh = RefreshToken.for_user(user)
                response = Response({'user': UserSerializer(user).data})
                self._set_auth_cookies(response, refresh)
                return response
            
            return Response(
                {'error': 'Authentication failed'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        except Exception as e:
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def _set_auth_cookies(self, response, refresh):
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


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        response = Response({'message': 'Logged out successfully'})
        response.delete_cookie(settings.JWT_AUTH_COOKIE)
        response.delete_cookie(settings.JWT_AUTH_REFRESH_COOKIE)
        return response


class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)
    
    def patch(self, request):
        serializer = UserSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)