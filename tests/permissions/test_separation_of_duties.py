"""
Tests for separation of duties enforcement.

Key security requirements tested:
1. Users cannot approve their own certificate requests
2. Super Admin limit (max 2)
3. Last Super Admin protection
"""

import pytest

from accounts.models import UserProfile
from core.permissions import can_user_approve_request
from core.models import PendingCertificateRequest
from tests.factories import (
    UserFactory,
    CertificateAuthorityFactory,
    PendingCertificateRequestFactory,
)


@pytest.mark.django_db
class TestSeparationOfDuties:
    """Tests for separation of duties in certificate approval."""

    def test_user_cannot_approve_own_request(self):
        """Test that a user cannot approve their own certificate request."""
        requester = UserFactory()
        requester.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
        requester.profile.save()

        ca = CertificateAuthorityFactory(created_by=requester)
        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.PENDING,
        )

        can_approve, reason = can_user_approve_request(requester, request)

        assert can_approve is False
        assert 'separation of duties' in reason.lower()

    def test_different_user_can_approve_request(self):
        """Test that a different user can approve a request."""
        requester = UserFactory()
        requester.profile.role = UserProfile.Role.CERTIFICATE_REQUESTER
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

    def test_super_admin_cannot_approve_own_request(self):
        """Test that even Super Admins cannot approve their own requests."""
        super_admin = UserFactory()
        super_admin.profile.role = UserProfile.Role.SUPER_ADMIN
        super_admin.profile.save()

        ca = CertificateAuthorityFactory(created_by=super_admin)
        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=super_admin,
            status=PendingCertificateRequest.Status.PENDING,
        )

        can_approve, reason = can_user_approve_request(super_admin, request)

        assert can_approve is False
        assert 'separation of duties' in reason.lower()

    def test_requester_cannot_approve_any_request(self):
        """Test that Certificate Requesters cannot approve any requests."""
        requester = UserFactory()
        requester.profile.role = UserProfile.Role.CERTIFICATE_REQUESTER
        requester.profile.save()

        other_requester = UserFactory()
        ca = CertificateAuthorityFactory(created_by=other_requester)
        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=other_requester,
            status=PendingCertificateRequest.Status.PENDING,
        )

        can_approve, reason = can_user_approve_request(requester, request)

        assert can_approve is False
        assert 'permission' in reason.lower()

    def test_auditor_cannot_approve_requests(self):
        """Test that Auditors cannot approve requests (read-only)."""
        auditor = UserFactory()
        auditor.profile.role = UserProfile.Role.AUDITOR
        auditor.profile.save()

        requester = UserFactory()
        ca = CertificateAuthorityFactory(created_by=requester)
        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.PENDING,
        )

        can_approve, reason = can_user_approve_request(auditor, request)

        assert can_approve is False
        assert 'permission' in reason.lower()

    def test_cannot_approve_non_pending_request(self):
        """Test that already approved/rejected requests cannot be approved."""
        approver = UserFactory()
        approver.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
        approver.profile.save()

        requester = UserFactory()
        ca = CertificateAuthorityFactory(created_by=approver)

        # Test approved request
        approved_request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.APPROVED,
        )

        can_approve, reason = can_user_approve_request(approver, approved_request)
        assert can_approve is False
        assert 'not pending' in reason.lower()

        # Test rejected request
        rejected_request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.REJECTED,
        )

        can_approve, reason = can_user_approve_request(approver, rejected_request)
        assert can_approve is False
        assert 'not pending' in reason.lower()

    def test_user_without_profile_cannot_approve(self):
        """Test that user without profile cannot approve requests."""
        from django.contrib.auth.models import User

        user = User.objects.create_user(
            username='noprofile',
            email='noprofile@example.com',
            password='test123'
        )
        user.profile.delete()

        requester = UserFactory()
        ca = CertificateAuthorityFactory(created_by=requester)
        request = PendingCertificateRequestFactory(
            ca=ca,
            requested_by=requester,
            status=PendingCertificateRequest.Status.PENDING,
        )

        can_approve, reason = can_user_approve_request(user, request)

        assert can_approve is False
        # User without profile has no permission to approve
        assert 'profile' in reason.lower() or 'permission' in reason.lower()


@pytest.mark.django_db
class TestSuperAdminLimitEnforcement:
    """Tests for Super Admin limit enforcement (max 2)."""

    def test_first_super_admin_allowed(self):
        """Test that the first Super Admin can be created."""
        user = UserFactory()
        user.profile.role = UserProfile.Role.SUPER_ADMIN
        user.profile.save()

        # Should succeed without error
        assert user.profile.role == UserProfile.Role.SUPER_ADMIN

    def test_second_super_admin_allowed(self):
        """Test that a second Super Admin can be created."""
        user1 = UserFactory()
        user1.profile.role = UserProfile.Role.SUPER_ADMIN
        user1.profile.save()

        user2 = UserFactory()
        user2.profile.role = UserProfile.Role.SUPER_ADMIN
        user2.profile.save()

        # Both should be Super Admins
        assert user1.profile.role == UserProfile.Role.SUPER_ADMIN
        assert user2.profile.role == UserProfile.Role.SUPER_ADMIN

    def test_third_super_admin_blocked(self):
        """Test that a third Super Admin cannot be created."""
        from django.core.exceptions import ValidationError

        user1 = UserFactory()
        user1.profile.role = UserProfile.Role.SUPER_ADMIN
        user1.profile.save()

        user2 = UserFactory()
        user2.profile.role = UserProfile.Role.SUPER_ADMIN
        user2.profile.save()

        user3 = UserFactory()
        user3.profile.role = UserProfile.Role.SUPER_ADMIN

        with pytest.raises(ValidationError, match='Cannot create more than 2 Super Admin'):
            user3.profile.save()


@pytest.mark.django_db
class TestLastSuperAdminProtection:
    """Tests for last Super Admin protection."""

    def test_cannot_delete_last_super_admin(self):
        """Test that the last Super Admin cannot be deleted."""
        user = UserFactory()
        user.profile.role = UserProfile.Role.SUPER_ADMIN
        user.profile.save()

        can_delete, reason = UserProfile.can_delete_user(user)

        assert can_delete is False
        assert 'last Super Admin' in reason

    def test_can_delete_one_of_two_super_admins(self):
        """Test that one of two Super Admins can be deleted."""
        user1 = UserFactory()
        user1.profile.role = UserProfile.Role.SUPER_ADMIN
        user1.profile.save()

        user2 = UserFactory()
        user2.profile.role = UserProfile.Role.SUPER_ADMIN
        user2.profile.save()

        can_delete, reason = UserProfile.can_delete_user(user1)

        assert can_delete is True
        assert reason == ''

    def test_cannot_demote_last_super_admin(self):
        """Test that the last Super Admin cannot be demoted."""
        user = UserFactory()
        user.profile.role = UserProfile.Role.SUPER_ADMIN
        user.profile.save()

        can_change, reason = UserProfile.can_change_role(
            user,
            UserProfile.Role.ADMINISTRATOR
        )

        assert can_change is False
        assert 'Cannot demote the last Super Admin' in reason

    def test_can_demote_one_of_two_super_admins(self):
        """Test that one of two Super Admins can be demoted."""
        user1 = UserFactory()
        user1.profile.role = UserProfile.Role.SUPER_ADMIN
        user1.profile.save()

        user2 = UserFactory()
        user2.profile.role = UserProfile.Role.SUPER_ADMIN
        user2.profile.save()

        can_change, reason = UserProfile.can_change_role(
            user1,
            UserProfile.Role.ADMINISTRATOR
        )

        assert can_change is True
        assert reason == ''

    def test_promote_after_demotion_allowed(self):
        """Test that promoting to Super Admin is allowed after demotion."""
        # Create two Super Admins
        user1 = UserFactory()
        user1.profile.role = UserProfile.Role.SUPER_ADMIN
        user1.profile.save()

        user2 = UserFactory()
        user2.profile.role = UserProfile.Role.SUPER_ADMIN
        user2.profile.save()

        # Demote one
        user1.profile.role = UserProfile.Role.ADMINISTRATOR
        user1.profile.save()

        # Now a third user should be able to become Super Admin
        user3 = UserFactory()
        can_change, reason = UserProfile.can_change_role(
            user3,
            UserProfile.Role.SUPER_ADMIN
        )

        assert can_change is True
        assert reason == ''
