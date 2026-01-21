"""
Tests for PendingCertificateRequest model.
"""

import pytest

from core.models import PendingCertificateRequest
from tests.factories import (
    PendingCertificateRequestFactory,
    CertificateAuthorityFactory,
    CertificateFactory,
    UserFactory,
)


@pytest.mark.django_db
class TestPendingCertificateRequestModel:
    """Tests for PendingCertificateRequest model basic functionality."""

    def test_create_pending_request(self):
        """Test creating a pending certificate request."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)
        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=user,
            common_name='test.example.com',
        )

        assert request.common_name == 'test.example.com'
        assert request.ca == ca
        assert request.requested_by == user
        assert request.status == PendingCertificateRequest.Status.PENDING

    def test_request_str_representation(self):
        """Test string representation of request."""
        user = UserFactory(username='testuser')
        request = PendingCertificateRequestFactory(
            common_name='test.example.com',
            requested_by=user,
        )

        str_repr = str(request)
        assert 'test.example.com' in str_repr
        assert 'testuser' in str_repr

    def test_request_ordering(self):
        """Test requests are ordered by requested_at descending."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)

        request1 = PendingCertificateRequestFactory(ca=ca, requested_by=user)
        request2 = PendingCertificateRequestFactory(ca=ca, requested_by=user)

        requests = PendingCertificateRequest.objects.all()
        assert requests[0] == request2  # Most recent first
        assert requests[1] == request1


@pytest.mark.django_db
class TestPendingRequestStatusProperties:
    """Tests for PendingCertificateRequest status properties."""

    def test_is_pending_true(self):
        """Test is_pending returns True for pending requests."""
        request = PendingCertificateRequestFactory(
            status=PendingCertificateRequest.Status.PENDING
        )
        assert request.is_pending is True

    def test_is_pending_false(self):
        """Test is_pending returns False for non-pending requests."""
        request = PendingCertificateRequestFactory(
            status=PendingCertificateRequest.Status.APPROVED
        )
        assert request.is_pending is False

    def test_is_approved_true(self):
        """Test is_approved returns True for approved requests."""
        request = PendingCertificateRequestFactory(
            status=PendingCertificateRequest.Status.APPROVED
        )
        assert request.is_approved is True

    def test_is_rejected_true(self):
        """Test is_rejected returns True for rejected requests."""
        request = PendingCertificateRequestFactory(
            status=PendingCertificateRequest.Status.REJECTED
        )
        assert request.is_rejected is True

    def test_is_issued_true(self):
        """Test is_issued returns True for issued requests."""
        request = PendingCertificateRequestFactory(
            status=PendingCertificateRequest.Status.ISSUED
        )
        assert request.is_issued is True


@pytest.mark.django_db
class TestPendingRequestApproval:
    """Tests for PendingCertificateRequest approval workflow."""

    def test_approve_request(self):
        """Test approving a pending request."""
        requester = UserFactory()
        reviewer = UserFactory()
        request = PendingCertificateRequestFactory(
            requested_by=requester,
            status=PendingCertificateRequest.Status.PENDING,
        )

        request.approve(reviewer)

        assert request.status == PendingCertificateRequest.Status.APPROVED
        assert request.reviewed_by == reviewer
        assert request.reviewed_at is not None

    def test_reject_request(self):
        """Test rejecting a pending request."""
        requester = UserFactory()
        reviewer = UserFactory()
        request = PendingCertificateRequestFactory(
            requested_by=requester,
            status=PendingCertificateRequest.Status.PENDING,
        )

        request.reject(reviewer, 'Invalid domain ownership')

        assert request.status == PendingCertificateRequest.Status.REJECTED
        assert request.reviewed_by == reviewer
        assert request.reviewed_at is not None
        assert request.rejection_reason == 'Invalid domain ownership'

    def test_mark_issued(self):
        """Test marking a request as issued with certificate."""
        requester = UserFactory()
        request = PendingCertificateRequestFactory(
            requested_by=requester,
            status=PendingCertificateRequest.Status.APPROVED,
        )
        certificate = CertificateFactory(created_by=requester)

        request.mark_issued(certificate)

        assert request.status == PendingCertificateRequest.Status.ISSUED
        assert request.issued_certificate == certificate


@pytest.mark.django_db
class TestPendingRequestFields:
    """Tests for PendingCertificateRequest field handling."""

    def test_san_fields_default_to_empty_lists(self):
        """Test SAN fields default to empty lists."""
        request = PendingCertificateRequestFactory()

        # These should be lists, not None
        assert isinstance(request.san_dns_names, list)
        assert isinstance(request.san_ip_addresses, list)
        assert isinstance(request.san_email_addresses, list)

    def test_san_dns_names_stored_correctly(self):
        """Test SAN DNS names are stored as JSON list."""
        dns_names = ['example.com', 'www.example.com', 'api.example.com']
        request = PendingCertificateRequestFactory(san_dns_names=dns_names)

        assert request.san_dns_names == dns_names
        request.refresh_from_db()
        assert request.san_dns_names == dns_names

    def test_san_ip_addresses_stored_correctly(self):
        """Test SAN IP addresses are stored as JSON list."""
        ip_addresses = ['192.168.1.1', '10.0.0.1']
        request = PendingCertificateRequestFactory(san_ip_addresses=ip_addresses)

        assert request.san_ip_addresses == ip_addresses
        request.refresh_from_db()
        assert request.san_ip_addresses == ip_addresses

    def test_san_email_addresses_stored_correctly(self):
        """Test SAN email addresses are stored as JSON list."""
        email_addresses = ['admin@example.com', 'security@example.com']
        request = PendingCertificateRequestFactory(san_email_addresses=email_addresses)

        assert request.san_email_addresses == email_addresses
        request.refresh_from_db()
        assert request.san_email_addresses == email_addresses

    def test_csr_pem_required(self):
        """Test that CSR PEM is stored correctly."""
        csr_pem = """-----BEGIN CERTIFICATE REQUEST-----
MIICijCCAXICAQAwRTELMAkGA1UEBhMCVVM=
-----END CERTIFICATE REQUEST-----"""
        request = PendingCertificateRequestFactory(csr_pem=csr_pem)

        assert request.csr_pem == csr_pem
