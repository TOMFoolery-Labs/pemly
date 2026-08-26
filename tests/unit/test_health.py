"""
Unit tests for the container health endpoint and the CFSSL auto-start gate.

Both exist because of the deployment refactor: the health endpoint is what the
container runtime polls, and the auto-start gate is what stops gunicorn workers
racing each other to spawn a CFSSL process now that it runs as its own service.
"""

import json
from unittest.mock import patch

from django.test import override_settings
from django.urls import reverse


class TestHealthEndpoint:
    """Tests for /healthz."""

    def test_reports_ok_when_database_reachable(self, client, db):
        with patch('core.views.health._cfssl_ok', return_value=True):
            response = client.get('/healthz')

        assert response.status_code == 200
        payload = json.loads(response.content)
        assert payload['status'] == 'ok'
        assert payload['database'] == 'ok'
        assert payload['cfssl'] == 'ok'

    def test_requires_no_authentication(self, client, db):
        """The runtime polls this without credentials, so it must not redirect."""
        with patch('core.views.health._cfssl_ok', return_value=True):
            response = client.get('/healthz')

        assert response.status_code == 200

    def test_stays_healthy_when_cfssl_is_down(self, client, db):
        """CFSSL has its own health check; the web UI is still usable without it."""
        with patch('core.views.health._cfssl_ok', return_value=False):
            response = client.get('/healthz')

        assert response.status_code == 200
        payload = json.loads(response.content)
        assert payload['status'] == 'ok'
        assert payload['cfssl'] == 'unavailable'

    def test_returns_503_when_database_unreachable(self, client, db):
        with patch('core.views.health._database_ok', return_value=False), \
             patch('core.views.health._cfssl_ok', return_value=True):
            response = client.get('/healthz')

        assert response.status_code == 503
        payload = json.loads(response.content)
        assert payload['status'] == 'error'
        assert payload['database'] == 'error'

    def test_is_resolvable_by_name(self):
        assert reverse('healthz') == '/healthz'

    def test_is_not_cached(self, client, db):
        """A cached health response would hide a failing container."""
        with patch('core.views.health._cfssl_ok', return_value=True):
            response = client.get('/healthz')

        assert 'no-cache' in response.headers.get('Cache-Control', '')


class TestCFSSLAutoStartGate:
    """core.apps.CoreConfig must not spawn CFSSL when auto-start is disabled."""

    @override_settings(CFSSL_AUTO_START=False)
    def test_does_not_start_cfssl_when_disabled(self):
        from core.apps import CoreConfig

        config = CoreConfig.create('core')
        with patch('core.services.get_cfssl_manager') as mock_manager:
            config._start_cfssl()

        # In the container deployment three gunicorn workers each reach this code
        # path; any one of them calling start() would recreate the spawn race.
        mock_manager.assert_not_called()

    @override_settings(CFSSL_AUTO_START=True)
    def test_starts_cfssl_when_enabled(self):
        """Local development still relies on the in-process manager."""
        from core.apps import CoreConfig

        config = CoreConfig.create('core')
        with patch('core.services.get_cfssl_manager') as mock_manager:
            mock_manager.return_value.start.return_value = True
            config._start_cfssl()

        mock_manager.return_value.start.assert_called_once()
