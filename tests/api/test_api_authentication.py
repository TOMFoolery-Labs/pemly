"""
Tests for API authentication mechanisms.
"""

import pytest
import hashlib
import secrets

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from core.models import APIKey
from tests.factories import UserFactory


@pytest.mark.django_db
class TestSessionAuthentication:
    """Tests for session-based authentication."""

    def test_authenticated_request_succeeds(self, manager_client):
        """Test authenticated request returns 200."""
        url = reverse('api:certificate-list')
        response = manager_client.get(url)

        assert response.status_code == status.HTTP_200_OK

    def test_unauthenticated_request_fails(self, api_client):
        """Test unauthenticated request returns 403."""
        url = reverse('api:certificate-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
class TestAPIKeyAuthentication:
    """Tests for API key authentication."""

    def create_api_key(self, user, name='Test Key'):
        """Helper to create an API key and return both key object and full key."""
        prefix = secrets.token_hex(4)
        secret = secrets.token_hex(32)
        full_key = f"pemly_{prefix}_{secret}"

        # Hash the secret for storage
        hashed = hashlib.sha256(secret.encode()).hexdigest()

        api_key = APIKey.objects.create(
            user=user,
            name=name,
            prefix=prefix,
            hashed_key=hashed,
        )

        return api_key, full_key

    def test_valid_api_key_authentication(self):
        """Test request with valid API key succeeds."""
        user = UserFactory()
        api_key, full_key = self.create_api_key(user)

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'ApiKey {full_key}')

        url = reverse('api:certificate-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_200_OK

    def test_invalid_api_key_authentication(self):
        """Test request with invalid API key fails."""
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='ApiKey pemly_invalid_key12345')

        url = reverse('api:certificate-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_expired_api_key_authentication(self):
        """Test request with expired API key fails."""
        from django.utils import timezone
        from datetime import timedelta

        user = UserFactory()
        api_key, full_key = self.create_api_key(user)
        api_key.expires_at = timezone.now() - timedelta(days=1)
        api_key.save()

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'ApiKey {full_key}')

        url = reverse('api:certificate-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_inactive_api_key_authentication(self):
        """Test request with inactive API key fails."""
        user = UserFactory()
        api_key, full_key = self.create_api_key(user)
        api_key.is_active = False
        api_key.save()

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'ApiKey {full_key}')

        url = reverse('api:certificate-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_api_key_last_used_updated(self):
        """Test that last_used_at is updated on API key use."""
        user = UserFactory()
        api_key, full_key = self.create_api_key(user)

        assert api_key.last_used_at is None

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'ApiKey {full_key}')

        url = reverse('api:certificate-list')
        client.get(url)  # Make request to update last_used_at

        api_key.refresh_from_db()
        assert api_key.last_used_at is not None

    def test_malformed_api_key_header(self):
        """Test request with malformed API key header fails."""
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='ApiKey not_a_valid_format')

        url = reverse('api:certificate-list')
        response = client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_wrong_auth_scheme(self):
        """Test request with wrong auth scheme is not processed."""
        user = UserFactory()
        api_key, full_key = self.create_api_key(user)

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {full_key}')

        url = reverse('api:certificate-list')
        response = client.get(url)

        # Should fall through to permission denied since Bearer is not handled
        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
class TestAPIKeyViewSet:
    """Tests for API Key management endpoints."""

    def test_list_own_api_keys(self, manager_client, manager_user):
        """Test user can list their own API keys."""
        # Create API keys for the user
        APIKey.objects.create(
            user=manager_user,
            name='Key 1',
            prefix='test1234',
            hashed_key='hash1',
        )
        APIKey.objects.create(
            user=manager_user,
            name='Key 2',
            prefix='test5678',
            hashed_key='hash2',
        )

        # Create API key for another user
        other_user = UserFactory()
        APIKey.objects.create(
            user=other_user,
            name='Other Key',
            prefix='othe1234',
            hashed_key='hash3',
        )

        url = reverse('api:apikey-list')
        response = manager_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) == 2
        for key in response.data['results']:
            assert key['name'] in ['Key 1', 'Key 2']

    def test_create_api_key(self, manager_client, manager_user):
        """Test creating a new API key."""
        url = reverse('api:apikey-list')
        data = {'name': 'New API Key'}
        response = manager_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['name'] == 'New API Key'
        # The full key should be returned on creation
        assert 'key' in response.data
        assert response.data['key'].startswith('pemly_')

    def test_delete_api_key(self, manager_client, manager_user):
        """Test deleting an API key."""
        api_key = APIKey.objects.create(
            user=manager_user,
            name='To Delete',
            prefix='del12345',
            hashed_key='hash',
        )

        url = reverse('api:apikey-detail', kwargs={'pk': api_key.id})
        response = manager_client.delete(url)

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not APIKey.objects.filter(id=api_key.id).exists()

    def test_cannot_delete_other_users_api_key(self, manager_client, manager_user):
        """Test user cannot delete another user's API key."""
        other_user = UserFactory()
        api_key = APIKey.objects.create(
            user=other_user,
            name='Other Key',
            prefix='othe1234',
            hashed_key='hash',
        )

        url = reverse('api:apikey-detail', kwargs={'pk': api_key.id})
        response = manager_client.delete(url)

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert APIKey.objects.filter(id=api_key.id).exists()
