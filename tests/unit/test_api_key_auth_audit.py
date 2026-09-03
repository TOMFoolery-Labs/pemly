"""
Regression test: a rejected API key must leave a trace.

APIKeyAuthentication raised AuthenticationFailed and recorded nothing, so key
probing - or a stale deployment hammering with a revoked key - was invisible.
The keys are 256-bit random, so this is about visibility, not a lockout.
"""

import pytest

from core.models import AuditLog


def failures():
    return AuditLog.objects.filter(action=AuditLog.Action.API_KEY_AUTH_FAILED)


@pytest.fixture
def api_url():
    return '/api/v1/certificates/'


@pytest.mark.django_db
class TestRejectedKeysAreAudited:
    def test_an_unknown_key_is_audited(self, client, api_url):
        client.get(api_url, HTTP_AUTHORIZATION='ApiKey pemly_abcd1234_nosuchsecret')

        entry = failures().get()
        assert entry.details['reason'] == 'no such key'
        assert entry.details['prefix'] == 'abcd1234'

    def test_a_malformed_key_is_audited(self, client, api_url):
        client.get(api_url, HTTP_AUTHORIZATION='ApiKey not-a-pemly-key')

        assert failures().get().details['reason'] == 'malformed prefix'

    def test_the_key_itself_is_never_recorded(self, client, api_url):
        secret = 'sup3rs3cretvalue'
        client.get(api_url, HTTP_AUTHORIZATION=f'ApiKey pemly_abcd1234_{secret}')

        assert secret not in str(failures().get().details)

    def test_a_request_with_no_key_records_nothing(self, client, api_url):
        """Anonymous browsing is not an authentication failure."""
        client.get(api_url)

        assert failures().count() == 0
