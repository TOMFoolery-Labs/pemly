"""
Production settings for pkife project.
"""

import os

import dj_database_url
from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F401, F403

DEBUG = False

# Fail closed: never run production with the insecure development fallbacks.
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
if not SECRET_KEY or SECRET_KEY == 'django-insecure-change-me-in-production':
    raise ImproperlyConfigured(
        "DJANGO_SECRET_KEY must be set to a unique secret value in production."
    )

# Private keys and stored credentials are encrypted at rest with this key; without
# it the app cannot protect CA/certificate keys, so require it explicitly.
if not os.environ.get('ENCRYPTION_KEY'):
    raise ImproperlyConfigured(
        "ENCRYPTION_KEY must be set in production to encrypt private keys at rest."
    )

ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', '').split(',')

# Database - use DATABASE_URL environment variable
DATABASES = {
    'default': dj_database_url.config(
        default='sqlite:///db.sqlite3',
        conn_max_age=600,
    )
}

# WhiteNoise for static file serving
MIDDLEWARE.insert(1, 'whitenoise.middleware.WhiteNoiseMiddleware')

STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

# Security settings for production
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'


def _env_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).lower() == 'true'


# HTTPS / secure-cookie settings. Secure by default; can be disabled via env vars
# for internal HTTP-only deployments (e.g. behind a trusted TLS-terminating proxy).
SECURE_SSL_REDIRECT = _env_bool('SECURE_SSL_REDIRECT', True)
SESSION_COOKIE_SECURE = _env_bool('SESSION_COOKIE_SECURE', True)
CSRF_COOKIE_SECURE = _env_bool('CSRF_COOKIE_SECURE', True)
SECURE_HSTS_SECONDS = int(os.environ.get('SECURE_HSTS_SECONDS', '31536000'))
SECURE_HSTS_INCLUDE_SUBDOMAINS = _env_bool('SECURE_HSTS_INCLUDE_SUBDOMAINS', True)
SECURE_HSTS_PRELOAD = _env_bool('SECURE_HSTS_PRELOAD', True)

# Honour the X-Forwarded-Proto header from a trusted TLS-terminating proxy so that
# SECURE_SSL_REDIRECT does not cause a redirect loop. The supported deployment always
# runs behind Traefik, which terminates TLS and sets this header, so it defaults on.
if _env_bool('USE_X_FORWARDED_PROTO', True):
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# The health endpoint is polled by the container runtime over plain HTTP on the
# internal network, so it must not be redirected to https.
SECURE_REDIRECT_EXEMPT = [r'^healthz/?$']

# CFSSL runs as its own container in the supported deployment; the app must not try to
# spawn it. Only local development uses the in-process manager (core/services/cfssl_manager).
CFSSL_AUTO_START = _env_bool('CFSSL_AUTO_START', False)

# CSRF trusted origins
csrf_origins = os.environ.get('CSRF_TRUSTED_ORIGINS', '')
CSRF_TRUSTED_ORIGINS = [o for o in csrf_origins.split(',') if o]

# Logging configuration for containers (stdout)
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': os.environ.get('DJANGO_LOG_LEVEL', 'INFO'),
            'propagate': False,
        },
        'core': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
