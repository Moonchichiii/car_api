"""
URL configuration for the car_api project.
This module defines the main URL patterns for the Django application.
It maps URL paths to their corresponding views or includes URL configurations
from other applications.
The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/stable/topics/http/urls/
"""
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('apps.users.urls')),
    path('social-auth/', include('social_django.urls', namespace='social')),
]
