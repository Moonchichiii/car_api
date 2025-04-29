"""URL patterns for the users app."""
from django.urls import path
from . import views

app_name = 'users'  # pylint: disable=invalid-name

urlpatterns = [
    path('register/', views.RegisterView.as_view(), name='register'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('google/', views.GoogleLoginView.as_view(), name='google-login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('profile/', views.UserProfileView.as_view(), name='profile'),
]
