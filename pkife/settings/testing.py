"""
Testing settings for pkife project.

Optimized for fast test execution with in-memory database and minimal overhead.
"""

from .base import *  # noqa: F401, F403

DEBUG = False

# Use in-memory SQLite for fast tests
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# Fast password hashing for tests
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Test encryption key (32 bytes base64-encoded for Fernet)
ENCRYPTION_KEY = 'dGVzdGluZ2VuY3J5cHRpb25rZXkxMjM0NTY3ODkwMTI='

# Disable CFSSL auto-start during tests
CFSSL_AUTO_START = False
CFSSL_API_URL = 'http://localhost:8888'
CFSSL_AUTH_KEY = ''

# Disable browser reload middleware
MIDDLEWARE = [m for m in MIDDLEWARE if 'BrowserReload' not in m]  # noqa: F405

# Console email backend for tests
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

# Disable logging during tests
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'handlers': {
        'null': {
            'class': 'logging.NullHandler',
        },
    },
    'root': {
        'handlers': ['null'],
        'level': 'CRITICAL',
    },
}

# Static files
STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'

# Allowed hosts for testing
ALLOWED_HOSTS = ['localhost', '127.0.0.1', 'testserver']

# Disable CSRF for API tests
REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES'] = [  # noqa: F405
    'rest_framework.authentication.SessionAuthentication',
    'core.authentication.APIKeyAuthentication',
]
