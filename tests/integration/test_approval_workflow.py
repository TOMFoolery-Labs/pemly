"""
Integration tests for certificate request approval workflow.

Tests the complete request-approval-issuance workflow including:
- Request submission
- Approval/rejection
- Separation of duties enforcement
- Certificate issuance from approved requests
"""

import pytest


from accounts.models import UserProfile
from core.models import PendingCertificateRequest
from core.permissions import can_user_approve_request
from tests.factories import (
    UserFactory,
    CertificateFactory,
    CertificateAuthorityFactory,
    PendingCertificateRequestFactory,
)


@pytest.mark.django_db
@pytest.mark.integration
class TestRequestSubmissionWorkflow:
    """Integration tests for certificate request submission."""

    def test_requester_submits_request(self):
        """Test Certificate Requester can submit a request."""
        requester = UserFactory()
        requester.profile.role = UserProfile.Role.CERTIFICATE_REQUESTER
        requester.profile.save()

        ca = CertificateAuthorityFactory(created_by=requester)

        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            common_name='request.example.com',
            san_dns_names=['request.example.com', 'www.request.example.com'],
        )

        assert request.status == PendingCertificateRequest.Status.PENDING
        assert request.requested_by == requester
        assert request.reviewed_by is None
        assert request.reviewed_at is None

    def test_request_preserves_all_fields(self):
        """Test all request fields are preserved correctly."""
        requester = UserFactory()
        ca = CertificateAuthorityFactory(created_by=requester)

        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            common_name='full.example.com',
            organization='Test Org',
            san_dns_names=['full.example.com', 'api.full.example.com'],
            san_ip_addresses=['192.168.1.1', '10.0.0.1'],
            san_email_addresses=['admin@example.com'],
            key_algorithm='ecdsa',
            key_size=256,
            validity_days=90,
        )

        # Refresh and verify all fields
        request.refresh_from_db()

        assert request.common_name == 'full.example.com'
        assert request.organization == 'Test Org'
        assert request.san_dns_names == ['full.example.com', 'api.full.example.com']
        assert request.san_ip_addresses == ['192.168.1.1', '10.0.0.1']
        assert request.san_email_addresses == ['admin@example.com']
        assert request.key_algorithm == 'ecdsa'
        assert request.key_size == 256
        assert request.validity_days == 90


@pytest.mark.django_db
@pytest.mark.integration
class TestApprovalWorkflow:
    """Integration tests for request approval workflow."""

    def test_manager_approves_request(self):
        """Test Certificate Manager can approve a request."""
        requester = UserFactory()
        requester.profile.role = UserProfile.Role.CERTIFICATE_REQUESTER
        requester.profile.save()

        manager = UserFactory()
        manager.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
        manager.profile.save()

        ca = CertificateAuthorityFactory(created_by=manager)

        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.PENDING,
        )

        # Approve the request
        request.approve(manager)

        assert request.status == PendingCertificateRequest.Status.APPROVED
        assert request.reviewed_by == manager
        assert request.reviewed_at is not None

    def test_admin_approves_request(self):
        """Test Administrator can approve a request."""
        requester = UserFactory()
        admin = UserFactory()
        admin.profile.role = UserProfile.Role.ADMINISTRATOR
        admin.profile.save()

        ca = CertificateAuthorityFactory(created_by=admin)

        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.PENDING,
        )

        request.approve(admin)

        assert request.status == PendingCertificateRequest.Status.APPROVED
        assert request.reviewed_by == admin

    def test_super_admin_approves_request(self):
        """Test Super Admin can approve a request."""
        requester = UserFactory()
        super_admin = UserFactory()
        super_admin.profile.role = UserProfile.Role.SUPER_ADMIN
        super_admin.profile.save()

        ca = CertificateAuthorityFactory(created_by=super_admin)

        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.PENDING,
        )

        request.approve(super_admin)

        assert request.status == PendingCertificateRequest.Status.APPROVED


@pytest.mark.django_db
@pytest.mark.integration
class TestRejectionWorkflow:
    """Integration tests for request rejection workflow."""

    def test_manager_rejects_request(self):
        """Test Certificate Manager can reject a request."""
        requester = UserFactory()
        manager = UserFactory()
        manager.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
        manager.profile.save()

        ca = CertificateAuthorityFactory(created_by=manager)

        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.PENDING,
        )

        rejection_reason = 'Domain ownership could not be verified'
        request.reject(manager, rejection_reason)

        assert request.status == PendingCertificateRequest.Status.REJECTED
        assert request.reviewed_by == manager
        assert request.reviewed_at is not None
        assert request.rejection_reason == rejection_reason

    def test_rejected_request_preserves_original_data(self):
        """Test rejected request preserves all original data."""
        requester = UserFactory()
        manager = UserFactory()
        manager.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
        manager.profile.save()

        ca = CertificateAuthorityFactory(created_by=manager)

        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            common_name='rejected.example.com',
            san_dns_names=['rejected.example.com'],
            status=PendingCertificateRequest.Status.PENDING,
        )

        request.reject(manager, 'Security concern')

        # Original data should be preserved
        assert request.common_name == 'rejected.example.com'
        assert request.san_dns_names == ['rejected.example.com']
        assert request.requested_by == requester


@pytest.mark.django_db
@pytest.mark.integration
class TestSeparationOfDutiesWorkflow:
    """Integration tests for separation of duties in approval workflow."""

    def test_user_cannot_approve_own_request_manager(self):
        """Test Certificate Manager cannot approve own request."""
        manager = UserFactory()
        manager.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
        manager.profile.save()

        ca = CertificateAuthorityFactory(created_by=manager)

        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=manager,  # Same user
            status=PendingCertificateRequest.Status.PENDING,
        )

        can_approve, reason = can_user_approve_request(manager, request)

        assert can_approve is False
        assert 'separation of duties' in reason.lower()

    def test_user_cannot_approve_own_request_super_admin(self):
        """Test Super Admin cannot approve own request."""
        super_admin = UserFactory()
        super_admin.profile.role = UserProfile.Role.SUPER_ADMIN
        super_admin.profile.save()

        ca = CertificateAuthorityFactory(created_by=super_admin)

        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=super_admin,  # Same user
            status=PendingCertificateRequest.Status.PENDING,
        )

        can_approve, reason = can_user_approve_request(super_admin, request)

        assert can_approve is False
        assert 'separation of duties' in reason.lower()

    def test_different_manager_can_approve(self):
        """Test a different manager can approve the request."""
        requester = UserFactory()
        requester.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
        requester.profile.save()

        approver = UserFactory()
        approver.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
        approver.profile.save()

        ca = CertificateAuthorityFactory(created_by=approver)

        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.PENDING,
        )

        can_approve, reason = can_user_approve_request(approver, request)

        assert can_approve is True
        assert reason == ''


@pytest.mark.django_db
@pytest.mark.integration
class TestIssuanceWorkflow:
    """Integration tests for certificate issuance from approved requests."""

    def test_mark_request_as_issued(self):
        """Test marking request as issued with certificate."""
        requester = UserFactory()
        manager = UserFactory()
        manager.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
        manager.profile.save()

        ca = CertificateAuthorityFactory(created_by=manager)

        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            common_name='issued.example.com',
            status=PendingCertificateRequest.Status.APPROVED,
            reviewed_by=manager,
        )

        # Create certificate from request
        cert = CertificateFactory(
            ca=ca,
            common_name=request.common_name,
            created_by=requester,
        )

        # Mark request as issued
        request.mark_issued(cert)

        assert request.status == PendingCertificateRequest.Status.ISSUED
        assert request.issued_certificate == cert

    def test_issued_request_links_to_certificate(self):
        """Test issued request maintains link to certificate."""
        requester = UserFactory()
        manager = UserFactory()
        ca = CertificateAuthorityFactory(created_by=manager)

        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            common_name='linked.example.com',
            status=PendingCertificateRequest.Status.APPROVED,
        )

        cert = CertificateFactory(
            ca=ca,
            common_name='linked.example.com',
            created_by=requester,
        )

        request.mark_issued(cert)

        # Verify bidirectional access
        assert request.issued_certificate == cert
        assert request.issued_certificate.common_name == 'linked.example.com'


@pytest.mark.django_db
@pytest.mark.integration
class TestWorkflowStatusTransitions:
    """Integration tests for request status transitions."""

    def test_pending_to_approved_transition(self):
        """Test pending -> approved transition."""
        requester = UserFactory()
        manager = UserFactory()
        manager.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
        manager.profile.save()

        ca = CertificateAuthorityFactory(created_by=manager)

        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.PENDING,
        )

        assert request.is_pending is True

        request.approve(manager)

        assert request.is_pending is False
        assert request.is_approved is True

    def test_pending_to_rejected_transition(self):
        """Test pending -> rejected transition."""
        requester = UserFactory()
        manager = UserFactory()
        manager.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
        manager.profile.save()

        ca = CertificateAuthorityFactory(created_by=manager)

        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.PENDING,
        )

        request.reject(manager, 'Invalid request')

        assert request.is_pending is False
        assert request.is_rejected is True

    def test_approved_to_issued_transition(self):
        """Test approved -> issued transition."""
        requester = UserFactory()
        manager = UserFactory()
        ca = CertificateAuthorityFactory(created_by=manager)

        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.APPROVED,
        )

        cert = CertificateFactory(ca=ca, created_by=requester)
        request.mark_issued(cert)

        assert request.is_approved is False
        assert request.is_issued is True
