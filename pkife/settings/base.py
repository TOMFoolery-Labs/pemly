"""
Base Django settings for pkife project.

Common settings shared between development and production.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Application version
VERSION = '0.11.0'

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'django-insecure-change-me-in-production')

# Encryption key for private keys at rest (Fernet)
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')

# Whether to trust the X-Forwarded-For header when determining the client IP for
# audit logs. Only enable this when running behind a trusted proxy that sets the
# header itself; otherwise clients can spoof their recorded IP address.
TRUST_X_FORWARDED_FOR = os.environ.get('TRUST_X_FORWARDED_FOR', 'false').lower() == 'true'

# CFSSL Configuration
CFSSL_API_URL = os.environ.get('CFSSL_API_URL', 'http://localhost:8888')
CFSSL_AUTH_KEY = os.environ.get('CFSSL_AUTH_KEY', '')

# CFSSL Process Management
CFSSL_AUTO_START = os.environ.get('CFSSL_AUTO_START', 'true').lower() == 'true'
CFSSL_BINARY_PATH = os.environ.get('CFSSL_BINARY_PATH', '')  # Auto-detect if empty
CFSSL_HOST = os.environ.get('CFSSL_HOST', 'localhost')
CFSSL_PORT = int(os.environ.get('CFSSL_PORT') or '8888')

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Third party apps
    'rest_framework',
    'drf_spectacular',
    # Local apps
    'core',
    'accounts',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'pkife.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'core.permissions.add_permission_context',
                'core.context_processors.app_settings',
            ],
        },
    },
]

WSGI_APPLICATION = 'pkife.wsgi.application'

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Login settings
# Login throttling. Failures are counted out of the audit log rather than a cache,
# so the limit holds across gunicorn workers and survives a restart - and every
# rejected attempt is visible to an auditor instead of only to a rate limiter.
# The per-username limit stops targeted guessing; the far looser per-address limit
# stops spraying without letting one office NAT lock out everyone behind it.
# `or` rather than a default argument: a `KEY=` line in .env yields '' and int('')
# would crash settings import, so the container never starts.
LOGIN_FAILURE_LIMIT = int(os.environ.get('LOGIN_FAILURE_LIMIT') or '10')
LOGIN_FAILURE_LIMIT_PER_IP = int(os.environ.get('LOGIN_FAILURE_LIMIT_PER_IP') or '50')
LOGIN_FAILURE_WINDOW_MINUTES = int(os.environ.get('LOGIN_FAILURE_WINDOW_MINUTES') or '15')

AUTHENTICATION_BACKENDS = ['accounts.backends.ThrottledModelBackend']

LOGIN_URL = 'accounts:login'
LOGIN_REDIRECT_URL = 'core:dashboard'
LOGOUT_REDIRECT_URL = 'accounts:login'

# REST Framework settings
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'core.authentication.APIKeyAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 100,
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
}

# drf-spectacular settings for OpenAPI/Swagger documentation
SPECTACULAR_SETTINGS = {
    # drf-spectacular serves the schema and Swagger UI with AllowAny by default,
    # ignoring DEFAULT_PERMISSION_CLASSES. On a host that is reachable from the
    # internet that hands an anonymous visitor the full API map of a certificate
    # authority, so the docs require a session like everything else.
    'SERVE_PERMISSIONS': ['rest_framework.permissions.IsAuthenticated'],
    'TITLE': 'PEMLY PKI API',
    'DESCRIPTION': 'REST API for automated certificate management',
    'VERSION': VERSION,
    'SERVE_INCLUDE_SCHEMA': False,
    'COMPONENT_SPLIT_REQUEST': True,
    'SCHEMA_PATH_PREFIX': '/api/v1',
}
