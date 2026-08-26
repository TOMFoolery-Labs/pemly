"""
Liveness/readiness endpoint for container orchestration.

Deliberately unauthenticated and cheap: it is polled by the container runtime every
few seconds. The database is the only hard requirement — CFSSL runs as its own
container with its own health check, and the web UI remains usable while it is down,
so its state is reported but does not fail the check.
"""

import logging

from django.db import connection
from django.http import JsonResponse
from django.views.decorators.cache import never_cache

logger = logging.getLogger(__name__)


def _database_ok() -> bool:
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
            cursor.fetchone()
        return True
    except Exception as exc:
        logger.warning(f"Health check: database unreachable: {exc}")
        return False


def _cfssl_ok() -> bool:
    try:
        from core.services.cfssl import CFSSLClient
        return CFSSLClient().health_check()
    except Exception:
        return False


@never_cache
def healthz(request):
    """Return 200 when the app can serve traffic, 503 otherwise."""
    database = _database_ok()
    payload = {
        'status': 'ok' if database else 'error',
        'database': 'ok' if database else 'error',
        'cfssl': 'ok' if _cfssl_ok() else 'unavailable',
    }
    return JsonResponse(payload, status=200 if database else 503)
