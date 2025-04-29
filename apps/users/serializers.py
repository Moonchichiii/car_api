"""Serializers for the users app."""
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    """Serializer for the User model."""
    class Meta:
        """Meta class for UserSerializer."""
        model = User
        fields = ('id', 'email', 'first_name', 'last_name', 'password')
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        """Create and return a new user."""
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )
        return user

class LoginSerializer(serializers.Serializer):
    """Serializer for user login."""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def create(self, validated_data):
        """Create method is not implemented for LoginSerializer."""
        raise NotImplementedError()

    def update(self, instance, validated_data):
        """Update method is not implemented for LoginSerializer."""
        raise NotImplementedError()
