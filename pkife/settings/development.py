"""
Development settings for pkife project.
"""

from .base import *  # noqa: F401, F403

DEBUG = True

ALLOWED_HOSTS = ['localhost', '127.0.0.1']

# Database - SQLite for development
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Add django-browser-reload for development
INSTALLED_APPS += [  # noqa: F405
    'django_browser_reload',
]

MIDDLEWARE += [  # noqa: F405
    'django_browser_reload.middleware.BrowserReloadMiddleware',
]

# Email backend for development - print to console
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
