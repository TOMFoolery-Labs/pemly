"""
Tests for Certificate API ViewSet.
"""

import pytest
from unittest.mock import patch, MagicMock

from django.urls import reverse
from rest_framework import status

from core.models import CertificateStatus
from tests.factories import (
    CertificateFactory,
    CertificateAuthorityFactory,
)


@pytest.mark.django_db
class TestCertificateViewSetList:
    """Tests for Certificate list endpoint."""

    def test_list_certificates_authenticated(self, manager_client, root_ca, manager_user):
        """Test authenticated user can list certificates."""
        CertificateFactory(ca=root_ca, created_by=manager_user)
        CertificateFactory(ca=root_ca, created_by=manager_user)

        url = reverse('api:certificate-list')
        response = manager_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) == 2

    def test_list_certificates_unauthenticated(self, api_client):
        """Test unauthenticated user cannot list certificates."""
        url = reverse('api:certificate-list')
        response = api_client.get(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_list_certificates_filter_by_status(self, manager_client, root_ca, manager_user):
        """Test filtering certificates by status."""
        CertificateFactory(ca=root_ca, status=CertificateStatus.ACTIVE, created_by=manager_user)
        CertificateFactory(ca=root_ca, status=CertificateStatus.REVOKED, created_by=manager_user)

        url = reverse('api:certificate-list')
        response = manager_client.get(url, {'status': 'active'})

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) == 1
        assert response.data['results'][0]['status'] == 'active'

    def test_list_certificates_filter_by_ca(self, manager_client, manager_user):
        """Test filtering certificates by CA."""
        ca1 = CertificateAuthorityFactory(created_by=manager_user)
        ca2 = CertificateAuthorityFactory(created_by=manager_user)
        CertificateFactory(ca=ca1, created_by=manager_user)
        CertificateFactory(ca=ca2, created_by=manager_user)

        url = reverse('api:certificate-list')
        response = manager_client.get(url, {'ca': str(ca1.id)})

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) == 1

    def test_list_certificates_search_by_common_name(self, manager_client, root_ca, manager_user):
        """Test searching certificates by common name."""
        CertificateFactory(ca=root_ca, common_name='api.example.com', created_by=manager_user)
        CertificateFactory(ca=root_ca, common_name='web.example.com', created_by=manager_user)

        url = reverse('api:certificate-list')
        response = manager_client.get(url, {'search': 'api'})

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) == 1
        assert 'api' in response.data['results'][0]['common_name']


@pytest.mark.django_db
class TestCertificateViewSetRetrieve:
    """Tests for Certificate retrieve endpoint."""

    def test_retrieve_certificate(self, manager_client, root_ca, manager_user):
        """Test retrieving a single certificate."""
        cert = CertificateFactory(ca=root_ca, created_by=manager_user)

        url = reverse('api:certificate-detail', kwargs={'pk': cert.id})
        response = manager_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert response.data['common_name'] == cert.common_name

    def test_retrieve_nonexistent_certificate(self, manager_client):
        """Test retrieving a nonexistent certificate returns 404."""
        import uuid

        url = reverse('api:certificate-detail', kwargs={'pk': uuid.uuid4()})
        response = manager_client.get(url)

        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestCertificateViewSetCreate:
    """Tests for Certificate create endpoint."""

    @patch('core.api_views.CFSSLClient')
    def test_create_certificate_manager(self, mock_cfssl_class, manager_client, manager_user):
        """Test Certificate Manager can create certificates."""
        # Setup mock
        mock_cfssl = MagicMock()
        mock_cfssl_class.return_value = mock_cfssl
        mock_cfssl.generate_key.return_value = {
            'private_key': '-----BEGIN RSA PRIVATE KEY-----\nTEST\n-----END RSA PRIVATE KEY-----',
            'csr': '-----BEGIN CERTIFICATE REQUEST-----\nTEST\n-----END CERTIFICATE REQUEST-----',
        }
        mock_cfssl.sign.return_value = {
            'certificate': '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----',
        }

        ca = CertificateAuthorityFactory(created_by=manager_user)
        ca.set_private_key('-----BEGIN RSA PRIVATE KEY-----\nCA KEY\n-----END RSA PRIVATE KEY-----')
        ca.save()

        url = reverse('api:certificate-list')
        data = {
            'ca': str(ca.id),
            'common_name': 'test.example.com',
            'type': 'server_tls',
            'key_algorithm': 'rsa',
            'key_size': 2048,
            'validity_days': 365,
        }
        response = manager_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['common_name'] == 'test.example.com'

    def test_create_certificate_requester_denied(self, requester_client, requester_user):
        """Test Certificate Requester cannot create certificates directly."""
        ca = CertificateAuthorityFactory(created_by=requester_user)

        url = reverse('api:certificate-list')
        data = {
            'ca': str(ca.id),
            'common_name': 'test.example.com',
            'type': 'server_tls',
            'key_algorithm': 'rsa',
            'key_size': 2048,
            'validity_days': 365,
        }
        response = requester_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_create_certificate_auditor_denied(self, auditor_client, auditor_user):
        """Test Auditor cannot create certificates."""
        ca = CertificateAuthorityFactory(created_by=auditor_user)

        url = reverse('api:certificate-list')
        data = {
            'ca': str(ca.id),
            'common_name': 'test.example.com',
            'type': 'server_tls',
            'key_algorithm': 'rsa',
            'key_size': 2048,
            'validity_days': 365,
        }
        response = auditor_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_create_certificate_ca_cannot_sign(self, manager_client, manager_user):
        """Test creating certificate with CA that cannot sign returns error."""
        ca = CertificateAuthorityFactory(
            created_by=manager_user,
            status='air_gapped'
        )
        ca.private_key_pem_encrypted = ''
        ca.save()

        url = reverse('api:certificate-list')
        data = {
            'ca': str(ca.id),
            'common_name': 'test.example.com',
            'type': 'server_tls',
            'key_algorithm': 'rsa',
            'key_size': 2048,
            'validity_days': 365,
        }
        response = manager_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'cannot sign' in response.data['detail'].lower()


@pytest.mark.django_db
class TestCertificateViewSetRevoke:
    """Tests for Certificate revoke endpoint."""

    def test_revoke_certificate_manager(self, manager_client, root_ca, manager_user):
        """Test Certificate Manager can revoke certificates."""
        cert = CertificateFactory(
            ca=root_ca,
            status=CertificateStatus.ACTIVE,
            created_by=manager_user
        )

        url = reverse('api:certificate-revoke', kwargs={'pk': cert.id})
        data = {'reason': 'key_compromise'}
        response = manager_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK
        cert.refresh_from_db()
        assert cert.status == CertificateStatus.REVOKED

    def test_revoke_certificate_requester_denied(self, requester_client, root_ca, requester_user):
        """Test Certificate Requester cannot revoke certificates."""
        cert = CertificateFactory(
            ca=root_ca,
            status=CertificateStatus.ACTIVE,
            created_by=requester_user
        )

        url = reverse('api:certificate-revoke', kwargs={'pk': cert.id})
        data = {'reason': 'key_compromise'}
        response = requester_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_revoke_already_revoked_certificate(self, manager_client, root_ca, manager_user):
        """Test revoking an already revoked certificate returns error."""
        cert = CertificateFactory(
            ca=root_ca,
            status=CertificateStatus.REVOKED,
            created_by=manager_user
        )

        url = reverse('api:certificate-revoke', kwargs={'pk': cert.id})
        data = {'reason': 'key_compromise'}
        response = manager_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'already revoked' in response.data['detail'].lower()


@pytest.mark.django_db
class TestCertificateViewSetDownload:
    """Tests for Certificate download endpoint."""

    def test_download_certificate_pem(self, manager_client, root_ca, manager_user):
        """Test downloading certificate in PEM format."""
        cert = CertificateFactory(
            ca=root_ca,
            certificate_pem='-----BEGIN CERTIFICATE-----\nTEST CERT\n-----END CERTIFICATE-----',
            created_by=manager_user
        )

        url = reverse('api:certificate-download', kwargs={'pk': cert.id})
        response = manager_client.get(url, {'output_format': 'pem'})

        assert response.status_code == status.HTTP_200_OK
        assert response.data['format'] == 'pem'
        assert 'BEGIN CERTIFICATE' in response.data['certificate']

    def test_download_certificate_unsupported_format(self, manager_client, root_ca, manager_user):
        """Test downloading certificate in unsupported format returns error."""
        cert = CertificateFactory(ca=root_ca, created_by=manager_user)

        url = reverse('api:certificate-download', kwargs={'pk': cert.id})
        response = manager_client.get(url, {'output_format': 'invalid'})

        assert response.status_code == status.HTTP_400_BAD_REQUEST
