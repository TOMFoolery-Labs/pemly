"""
Tests for API key parsing and failure auditing.

Two things lived here. generate_api_key() builds the secret with token_urlsafe,
whose alphabet includes '_', and authenticate() split the key on underscores -
so roughly half of all issued keys were rejected as malformed. And a rejected
key recorded nothing, so probing was invisible.
"""

import pytest

from core.authentication import generate_api_key
from core.models import APIKey, AuditLog


API_URL = '/api/v1/certificates/'


def failures():
    return AuditLog.objects.filter(action=AuditLog.Action.API_KEY_AUTH_FAILED)


@pytest.fixture
def issued_key(super_admin_user):
    """A key exactly as the UI would issue it."""
    full_key, prefix, hashed = generate_api_key()
    APIKey.objects.create(name='t', prefix=prefix, hashed_key=hashed, user=super_admin_user)
    return full_key


@pytest.mark.django_db
class TestIssuedKeysAuthenticate:
    def test_a_key_with_underscores_in_the_secret_works(self, client, super_admin_user):
        """The regression: ~55% of generated keys were rejected as malformed."""
        prefix = 'abcd1234'
        secret = 'part_with_under_scores_in_it_x'
        from core.authentication import hash_api_key
        APIKey.objects.create(
            name='t', prefix=prefix, hashed_key=hash_api_key(secret), user=super_admin_user
        )

        response = client.get(API_URL, HTTP_AUTHORIZATION=f'ApiKey pemly_{prefix}_{secret}')

        assert response.status_code == 200
        assert failures().count() == 0

    def test_every_generated_key_authenticates(self, client, super_admin_user):
        for _ in range(40):
            full_key, prefix, hashed = generate_api_key()
            APIKey.objects.create(name='t', prefix=prefix, hashed_key=hashed, user=super_admin_user)

            response = client.get(API_URL, HTTP_AUTHORIZATION=f'ApiKey {full_key}')

            assert response.status_code == 200, full_key

    def test_the_prefix_never_contains_the_separator(self):
        assert all('_' not in generate_api_key()[1] for _ in range(200))


@pytest.mark.django_db
class TestRejectedKeysAreAudited:
    def test_an_unknown_key_is_audited(self, client):
        client.get(API_URL, HTTP_AUTHORIZATION='ApiKey pemly_abcd1234_nosuchsecret')

        entry = failures().get()
        assert entry.details == {'prefix': 'abcd1234', 'reason': 'no such key'}

    def test_a_malformed_key_is_audited(self, client):
        client.get(API_URL, HTTP_AUTHORIZATION='ApiKey not-a-pemly-key')

        assert failures().get().details['reason'] == 'malformed key'

    def test_the_key_itself_is_never_recorded(self, client):
        client.get(API_URL, HTTP_AUTHORIZATION='ApiKey pemly_abcd1234_sup3rs3cretvalue')

        assert 'sup3rs3cretvalue' not in str(failures().get().details)

    def test_a_request_with_no_key_records_nothing(self, client):
        client.get(API_URL)

        assert failures().count() == 0

    def test_rows_are_capped_per_address(self, client):
        """A prober must not be able to write one audit row per request."""
        for n in range(50):
            client.get(API_URL, HTTP_AUTHORIZATION=f'ApiKey pemly_abcd1234_junk{n}')

        assert failures().count() == 1

    def test_a_failed_audit_write_still_returns_401(self, client, monkeypatch):
        from core import authentication

        def boom(*args, **kwargs):
            raise RuntimeError("database is away")

        monkeypatch.setattr(authentication.AuditLog, 'log', boom)

        response = client.get(API_URL, HTTP_AUTHORIZATION='ApiKey pemly_abcd1234_nope')

        assert response.status_code in (401, 403)
