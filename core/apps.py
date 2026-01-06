import logging
import os
import sys

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'

    def ready(self):
        """Called when Django app is ready."""
        # Don't start CFSSL in these scenarios:
        # - Running migrations
        # - Running other management commands (except runserver)
        # - In the reloader's parent process
        if any(cmd in sys.argv for cmd in ['migrate', 'makemigrations', 'collectstatic', 'shell', 'test']):
            return

        # In development, Django runs the reloader which spawns a child process.
        # We only want to start CFSSL in the child process (RUN_MAIN=true).
        # In production (gunicorn/uwsgi), RUN_MAIN won't be set, so we start anyway.
        if os.environ.get('RUN_MAIN') == 'true' or 'runserver' not in sys.argv:
            self._start_cfssl()

    def _start_cfssl(self):
        """Start the CFSSL server if configured."""
        from django.conf import settings as django_settings

        # Use Django settings during startup to avoid database access
        auto_start = getattr(django_settings, 'CFSSL_AUTO_START', True)
        if not auto_start:
            logger.info("CFSSL auto-start is disabled")
            return

        # Get config from Django settings to avoid database access during startup
        host = getattr(django_settings, 'CFSSL_HOST', 'localhost')
        port = int(getattr(django_settings, 'CFSSL_PORT', 8888))
        binary_path = getattr(django_settings, 'CFSSL_BINARY_PATH', None)

        try:
            from core.services import get_cfssl_manager
            manager = get_cfssl_manager()

            # Pass config explicitly to avoid database queries during startup
            if manager.start(host=host, port=port, binary_path=binary_path):
                logger.info("CFSSL manager initialized successfully")
            else:
                logger.warning(
                    "CFSSL could not be started automatically. "
                    "You may need to start it manually or install the cfssl binary."
                )
        except Exception as e:
            logger.error(f"Error initializing CFSSL manager: {e}")
