"""Django settings for Car Rental project."""
from datetime import timedelta
from pathlib import Path

from decouple import Csv, config

# CORE CONFIGURATION

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = config("DJANGO_SECRET_KEY")
DEBUG = config("DJANGO_DEBUG", default=True, cast=bool)
ALLOWED_HOSTS = config("DJANGO_ALLOWED_HOSTS", default="", cast=Csv()) or [
    "localhost",
    "127.0.0.1",
]
ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"


# APPLICATIONS

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.sites",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third-party apps
    "django_cryptography",
    # REST Framework
    "rest_framework",
    "rest_framework.authtoken",
    # JWT Authentication
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    # Authentication
    "dj_rest_auth",
    "dj_rest_auth.registration",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    # "allauth.socialaccount.providers.google",
    # CORS
    "corsheaders",
    # Applications
    "apps.users",
]


# MIDDLEWARE
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "allauth.account.middleware.AccountMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "csp.middleware.CSPMiddleware",
]


AUTH_PASSWORD_VALIDATORS = [
  {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
  {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
  {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
  {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]


# TEMPLATES
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# DATABASE
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "car_rental",
        "USER": "postgres",
        "PASSWORD": config("DB_PASSWORD"),
        "HOST": "localhost",
        "PORT": "5433",
        "CONN_MAX_AGE": 600,
        "OPTIONS": {"sslmode": "prefer"},
    }
}


# AUTHENTICATION
AUTH_USER_MODEL = "users.User"

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]

SITE_ID = 1

SESSION_COOKIE_SECURE   = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE      = True
CSRF_COOKIE_HTTPONLY    = True

# REST FRAMEWORK & JWT

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "dj_rest_auth.jwt_auth.JWTCookieAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=10),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=3),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
}

REST_AUTH = {
    "USE_JWT": True,
    "JWT_AUTH_COOKIE": "auth",
    "JWT_AUTH_REFRESH_COOKIE": "refresh",
    "JWT_AUTH_COOKIE_HTTP_ONLY": True,
    "JWT_AUTH_COOKIE_SECURE": not DEBUG,
    "JWT_AUTH_COOKIE_SAMESITE": "Lax",
    # Custom registration & login serializer
    "LOGIN_SERIALIZER": "apps.users.serializers.CustomLoginSerializer",
    "REGISTER_SERIALIZER": "apps.users.serializers.CustomRegisterSerializer",
}


# ALLAUTH SETTINGS
ACCOUNT_ADAPTER = "apps.users.adapters.CustomAccountAdapter"
ACCOUNT_USER_MODEL_USERNAME_FIELD = "email"

# Login and signup configuration
ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*", "password2*"]
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_LOGIN_METHODS = {"email"}

# Authentication settings (backawrds compatibility)
ACCOUNT_AUTHENTICATION_METHOD = "email"

# UX settings
ACCOUNT_SESSION_REMEMBER = True
ACCOUNT_LOGOUT_ON_GET = False


# EMAIL CONFIGURATION

# Toggle for email verification "True for Production"
EMAIL_VERIFICATION_ENABLED = config(
    "EMAIL_VERIFICATION_ENABLED", default=False, cast=bool
)

# Email verification settings
ACCOUNT_EMAIL_VERIFICATION = "none"

# Email confirmation settings (when verification is enabled)
ACCOUNT_CONFIRM_EMAIL_ON_GET = EMAIL_VERIFICATION_ENABLED
ACCOUNT_EMAIL_CONFIRMATION_EXPIRE_DAYS = 1
ACCOUNT_EMAIL_CONFIRMATION_HMAC = False

# Production email settings

# ACCOUNT_EMAIL_SUBJECT_PREFIX = "[Car Rental] "
# EMAIL_VERIFICATION_ENABLED = True

# Email verification settings
# ACCOUNT_EMAIL_VERIFICATION = "mandatory"

# Email confirmation settings
# ACCOUNT_CONFIRM_EMAIL_ON_GET = True
# ACCOUNT_EMAIL_CONFIRMATION_EXPIRE_DAYS = 1
# ACCOUNT_EMAIL_SUBJECT_PREFIX = "[Car Rental] "


# Email backend configuration
if DEBUG:
    if EMAIL_VERIFICATION_ENABLED:
        # Development with real emails
        EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
        EMAIL_HOST = "smtp.gmail.com"
        EMAIL_PORT = 587
        EMAIL_USE_TLS = True
        EMAIL_HOST_USER = config("GMAIL_ADDRESS")
        EMAIL_HOST_PASSWORD = config("GMAIL_APP_PASSWORD")
        DEFAULT_FROM_EMAIL = EMAIL_HOST_USER
    else:
        # Development without email verification
        EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
else:
    # Production email settings
    EMAIL_BACKEND = config(
        "EMAIL_BACKEND", default="django.core.mail.backends.smtp.EmailBackend"
    )
    EMAIL_HOST = config("EMAIL_HOST", default="smtp.gmail.com")
    EMAIL_PORT = config("EMAIL_PORT", default=587, cast=int)
    EMAIL_USE_TLS = config("EMAIL_USE_TLS", default=True, cast=bool)
    EMAIL_HOST_USER = config("EMAIL_HOST_USER")
    EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD")
    DEFAULT_FROM_EMAIL = config("DEFAULT_FROM_EMAIL", default="noreply@car-rental.com")


# CORS SETTINGS
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = config("CORS_ALLOWED_ORIGINS", default="", cast=Csv()) or [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]


SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC  = ("'self'", "localhost:5173")

REFERRER_POLICY = "same-origin"
X_CONTENT_SECURITY_POLICY = "default-src 'self';"

# INTERNATIONALIZATION
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True


# STATIC FILES

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
