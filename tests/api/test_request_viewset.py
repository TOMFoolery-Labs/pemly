"""
Tests for PendingCertificateRequest API ViewSet.
"""

import pytest
from unittest.mock import patch

from django.urls import reverse
from rest_framework import status

from core.models import PendingCertificateRequest
from tests.factories import (
    UserFactory,
    PendingCertificateRequestFactory,
)


@pytest.mark.django_db
class TestRequestViewSetList:
    """Tests for PendingCertificateRequest list endpoint."""

    def test_list_requests_manager_sees_all(self, manager_client, root_ca, manager_user):
        """Test Certificate Manager sees all pending requests."""
        requester1 = UserFactory()
        requester2 = UserFactory()

        PendingCertificateRequestFactory(ca=root_ca, requested_by=requester1)
        PendingCertificateRequestFactory(ca=root_ca, requested_by=requester2)

        url = reverse('api:request-list')
        response = manager_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) == 2

    def test_list_requests_requester_sees_only_own(self, requester_client, root_ca, requester_user):
        """Test Certificate Requester only sees their own requests."""
        other_user = UserFactory()

        PendingCertificateRequestFactory(ca=root_ca, requested_by=requester_user)
        PendingCertificateRequestFactory(ca=root_ca, requested_by=other_user)

        url = reverse('api:request-list')
        response = requester_client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) == 1

    def test_list_requests_filter_by_status(self, manager_client, root_ca, manager_user):
        """Test filtering requests by status."""
        requester = UserFactory()

        PendingCertificateRequestFactory(
            ca=root_ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.PENDING
        )
        PendingCertificateRequestFactory(
            ca=root_ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.REJECTED
        )

        url = reverse('api:request-list')
        response = manager_client.get(url, {'status': 'pending'})

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) == 1
        assert response.data['results'][0]['status'] == 'pending'


@pytest.mark.django_db
class TestRequestViewSetCreate:
    """Tests for PendingCertificateRequest create endpoint."""

    def test_create_request_requester(self, requester_client, root_ca, requester_user):
        """Test Certificate Requester can submit a certificate request."""
        url = reverse('api:request-list')
        data = {
            'ca': str(root_ca.id),
            'common_name': 'request.example.com',
            'type': 'server_tls',
            'key_algorithm': 'rsa',
            'key_size': 2048,
            'validity_days': 365,
            'csr_pem': '-----BEGIN CERTIFICATE REQUEST-----\nTEST CSR\n-----END CERTIFICATE REQUEST-----',
        }
        response = requester_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['common_name'] == 'request.example.com'
        assert response.data['status'] == 'pending'

    def test_create_request_unauthenticated(self, api_client, root_ca):
        """Test unauthenticated users cannot submit requests."""
        url = reverse('api:request-list')
        data = {
            'ca': str(root_ca.id),
            'common_name': 'request.example.com',
            'type': 'server_tls',
            'csr_pem': '-----BEGIN CERTIFICATE REQUEST-----\nTEST\n-----END CERTIFICATE REQUEST-----',
        }
        response = api_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
class TestRequestViewSetApprove:
    """Tests for PendingCertificateRequest approve endpoint."""

    @patch('core.api_views.issue_certificate_from_csr')
    def test_approve_request_manager(self, mock_issue, manager_client, root_ca, manager_user):
        """Test Certificate Manager can approve requests."""
        from django.utils import timezone

        mock_issue.return_value = {
            'certificate': '-----BEGIN CERTIFICATE-----\nISSUED\n-----END CERTIFICATE-----',
            'serial_number': 'abc123',
            'not_before': timezone.now(),
            'not_after': timezone.now(),
        }

        requester = UserFactory()
        request = PendingCertificateRequestFactory(
            ca=root_ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.PENDING,
        )

        url = reverse('api:request-approve', kwargs={'pk': request.id})
        response = manager_client.post(url, format='json')

        assert response.status_code == status.HTTP_200_OK
        assert 'certificate_id' in response.data

    def test_approve_own_request_denied(self, manager_client, root_ca, manager_user):
        """Test user cannot approve their own request (separation of duties)."""
        request = PendingCertificateRequestFactory(
            ca=root_ca,
            requested_by=manager_user,  # Same as approver
            status=PendingCertificateRequest.Status.PENDING,
        )

        url = reverse('api:request-approve', kwargs={'pk': request.id})
        response = manager_client.post(url, format='json')

        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert 'cannot approve your own' in response.data['detail'].lower()

    def test_approve_request_requester_denied(self, requester_client, root_ca, requester_user):
        """Test Certificate Requester cannot approve requests."""
        other_user = UserFactory()
        request = PendingCertificateRequestFactory(
            ca=root_ca,
            requested_by=other_user,
            status=PendingCertificateRequest.Status.PENDING,
        )

        url = reverse('api:request-approve', kwargs={'pk': request.id})
        response = requester_client.post(url, format='json')

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_approve_non_pending_request(self, manager_client, root_ca, manager_user):
        """Test approving a non-pending request returns error."""
        requester = UserFactory()
        request = PendingCertificateRequestFactory(
            ca=root_ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.REJECTED,
        )

        url = reverse('api:request-approve', kwargs={'pk': request.id})
        response = manager_client.post(url, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'pending' in response.data['detail'].lower()


@pytest.mark.django_db
class TestRequestViewSetReject:
    """Tests for PendingCertificateRequest reject endpoint."""

    def test_reject_request_manager(self, manager_client, root_ca, manager_user):
        """Test Certificate Manager can reject requests."""
        requester = UserFactory()
        request = PendingCertificateRequestFactory(
            ca=root_ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.PENDING,
        )

        url = reverse('api:request-reject', kwargs={'pk': request.id})
        data = {'reason': 'Domain ownership not verified'}
        response = manager_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_200_OK

        request.refresh_from_db()
        assert request.status == PendingCertificateRequest.Status.REJECTED
        assert request.rejection_reason == 'Domain ownership not verified'

    def test_reject_request_requester_denied(self, requester_client, root_ca, requester_user):
        """Test Certificate Requester cannot reject requests."""
        other_user = UserFactory()
        request = PendingCertificateRequestFactory(
            ca=root_ca,
            requested_by=other_user,
            status=PendingCertificateRequest.Status.PENDING,
        )

        url = reverse('api:request-reject', kwargs={'pk': request.id})
        data = {'reason': 'Test rejection'}
        response = requester_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_reject_non_pending_request(self, manager_client, root_ca, manager_user):
        """Test rejecting a non-pending request returns error."""
        requester = UserFactory()
        request = PendingCertificateRequestFactory(
            ca=root_ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.APPROVED,
        )

        url = reverse('api:request-reject', kwargs={'pk': request.id})
        data = {'reason': 'Test rejection'}
        response = manager_client.post(url, data, format='json')

        assert response.status_code == status.HTTP_400_BAD_REQUEST
