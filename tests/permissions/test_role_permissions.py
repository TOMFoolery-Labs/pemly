"""
Tests for RBAC role permissions.
"""

import pytest
from django.contrib.auth.models import User, AnonymousUser
from django.core.exceptions import PermissionDenied
from django.test import RequestFactory

from accounts.models import UserProfile
from core.permissions import (
    user_can_manage_users,
    user_can_manage_cas,
    user_can_manage_settings,
    user_can_issue_certificates,
    user_can_revoke_certificates,
    user_can_approve_requests,
    user_can_view_audit_log,
    user_can_view_all_certificates,
    user_is_read_only,
    get_certificates_for_user,
    get_pending_requests_for_user,
    RoleRequiredMixin,
    SuperAdminRequiredMixin,
    AdminOrSuperAdminRequiredMixin,
    CanManageCertificatesMixin,
    CanViewAuditLogMixin,
    NotRequesterMixin,
    NotAuditorMixin,
)
from core.models import Certificate, PendingCertificateRequest
from tests.factories import (
    UserFactory,
    CertificateFactory,
    CertificateAuthorityFactory,
    PendingCertificateRequestFactory,
)


@pytest.mark.django_db
class TestPermissionHelperFunctions:
    """Tests for permission helper functions."""

    @pytest.mark.parametrize('role,expected', [
        (UserProfile.Role.SUPER_ADMIN, True),
        (UserProfile.Role.ADMINISTRATOR, False),
        (UserProfile.Role.CERTIFICATE_MANAGER, False),
        (UserProfile.Role.CERTIFICATE_REQUESTER, False),
        (UserProfile.Role.AUDITOR, False),
    ])
    def test_user_can_manage_users(self, role, expected):
        """Test user_can_manage_users for all roles."""
        user = UserFactory()
        user.profile.role = role
        user.profile.save()

        assert user_can_manage_users(user) == expected

    @pytest.mark.parametrize('role,expected', [
        (UserProfile.Role.SUPER_ADMIN, True),
        (UserProfile.Role.ADMINISTRATOR, True),
        (UserProfile.Role.CERTIFICATE_MANAGER, False),
        (UserProfile.Role.CERTIFICATE_REQUESTER, False),
        (UserProfile.Role.AUDITOR, False),
    ])
    def test_user_can_manage_cas(self, role, expected):
        """Test user_can_manage_cas for all roles."""
        user = UserFactory()
        user.profile.role = role
        user.profile.save()

        assert user_can_manage_cas(user) == expected

    @pytest.mark.parametrize('role,expected', [
        (UserProfile.Role.SUPER_ADMIN, True),
        (UserProfile.Role.ADMINISTRATOR, True),
        (UserProfile.Role.CERTIFICATE_MANAGER, False),
        (UserProfile.Role.CERTIFICATE_REQUESTER, False),
        (UserProfile.Role.AUDITOR, False),
    ])
    def test_user_can_manage_settings(self, role, expected):
        """Test user_can_manage_settings for all roles."""
        user = UserFactory()
        user.profile.role = role
        user.profile.save()

        assert user_can_manage_settings(user) == expected

    @pytest.mark.parametrize('role,expected', [
        (UserProfile.Role.SUPER_ADMIN, True),
        (UserProfile.Role.ADMINISTRATOR, True),
        (UserProfile.Role.CERTIFICATE_MANAGER, True),
        (UserProfile.Role.CERTIFICATE_REQUESTER, False),
        (UserProfile.Role.AUDITOR, False),
    ])
    def test_user_can_issue_certificates(self, role, expected):
        """Test user_can_issue_certificates for all roles."""
        user = UserFactory()
        user.profile.role = role
        user.profile.save()

        assert user_can_issue_certificates(user) == expected

    @pytest.mark.parametrize('role,expected', [
        (UserProfile.Role.SUPER_ADMIN, True),
        (UserProfile.Role.ADMINISTRATOR, True),
        (UserProfile.Role.CERTIFICATE_MANAGER, True),
        (UserProfile.Role.CERTIFICATE_REQUESTER, False),
        (UserProfile.Role.AUDITOR, False),
    ])
    def test_user_can_revoke_certificates(self, role, expected):
        """Test user_can_revoke_certificates for all roles."""
        user = UserFactory()
        user.profile.role = role
        user.profile.save()

        assert user_can_revoke_certificates(user) == expected

    @pytest.mark.parametrize('role,expected', [
        (UserProfile.Role.SUPER_ADMIN, True),
        (UserProfile.Role.ADMINISTRATOR, True),
        (UserProfile.Role.CERTIFICATE_MANAGER, True),
        (UserProfile.Role.CERTIFICATE_REQUESTER, False),
        (UserProfile.Role.AUDITOR, False),
    ])
    def test_user_can_approve_requests(self, role, expected):
        """Test user_can_approve_requests for all roles."""
        user = UserFactory()
        user.profile.role = role
        user.profile.save()

        assert user_can_approve_requests(user) == expected

    @pytest.mark.parametrize('role,expected', [
        (UserProfile.Role.SUPER_ADMIN, True),
        (UserProfile.Role.ADMINISTRATOR, True),
        (UserProfile.Role.CERTIFICATE_MANAGER, True),
        (UserProfile.Role.CERTIFICATE_REQUESTER, False),
        (UserProfile.Role.AUDITOR, True),
    ])
    def test_user_can_view_audit_log(self, role, expected):
        """Test user_can_view_audit_log for all roles."""
        user = UserFactory()
        user.profile.role = role
        user.profile.save()

        assert user_can_view_audit_log(user) == expected

    @pytest.mark.parametrize('role,expected', [
        (UserProfile.Role.SUPER_ADMIN, True),
        (UserProfile.Role.ADMINISTRATOR, True),
        (UserProfile.Role.CERTIFICATE_MANAGER, True),
        (UserProfile.Role.CERTIFICATE_REQUESTER, False),
        (UserProfile.Role.AUDITOR, True),
    ])
    def test_user_can_view_all_certificates(self, role, expected):
        """Test user_can_view_all_certificates for all roles."""
        user = UserFactory()
        user.profile.role = role
        user.profile.save()

        assert user_can_view_all_certificates(user) == expected

    @pytest.mark.parametrize('role,expected', [
        (UserProfile.Role.SUPER_ADMIN, False),
        (UserProfile.Role.ADMINISTRATOR, False),
        (UserProfile.Role.CERTIFICATE_MANAGER, False),
        (UserProfile.Role.CERTIFICATE_REQUESTER, False),
        (UserProfile.Role.AUDITOR, True),
    ])
    def test_user_is_read_only(self, role, expected):
        """Test user_is_read_only for all roles."""
        user = UserFactory()
        user.profile.role = role
        user.profile.save()

        assert user_is_read_only(user) == expected

    def test_permissions_without_profile(self):
        """Test all permission functions return False for user without profile."""
        user = User.objects.create_user(
            username='noprofile',
            email='noprofile@example.com',
            password='test123'
        )
        user.profile.delete()

        assert user_can_manage_users(user) is False
        assert user_can_manage_cas(user) is False
        assert user_can_manage_settings(user) is False
        assert user_can_issue_certificates(user) is False
        assert user_can_revoke_certificates(user) is False
        assert user_can_approve_requests(user) is False
        assert user_can_view_audit_log(user) is False
        assert user_can_view_all_certificates(user) is False
        assert user_is_read_only(user) is False


@pytest.mark.django_db
class TestQuerysetFiltering:
    """Tests for queryset filtering based on user role."""

    def test_get_certificates_for_requester(self):
        """Test Certificate Requesters only see their own certificates."""
        requester = UserFactory()
        requester.profile.role = UserProfile.Role.CERTIFICATE_REQUESTER
        requester.profile.save()

        other_user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=other_user)

        # Create certificates by requester and other user
        own_cert = CertificateFactory(ca=ca, created_by=requester)
        CertificateFactory(ca=ca, created_by=other_user)

        certs = get_certificates_for_user(requester)

        assert certs.count() == 1
        assert own_cert in certs

    def test_get_certificates_for_manager(self):
        """Test Certificate Managers see all certificates."""
        manager = UserFactory()
        manager.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
        manager.profile.save()

        other_user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=other_user)

        CertificateFactory(ca=ca, created_by=manager)
        CertificateFactory(ca=ca, created_by=other_user)

        certs = get_certificates_for_user(manager)

        assert certs.count() == 2

    def test_get_pending_requests_for_requester(self):
        """Test Certificate Requesters only see their own requests."""
        requester = UserFactory()
        requester.profile.role = UserProfile.Role.CERTIFICATE_REQUESTER
        requester.profile.save()

        other_user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=other_user)

        # Create requests by requester and other user
        own_request = PendingCertificateRequestFactory(ca=ca, requested_by=requester)
        PendingCertificateRequestFactory(ca=ca, requested_by=other_user)

        requests = get_pending_requests_for_user(requester)

        assert requests.count() == 1
        assert own_request in requests

    def test_get_pending_requests_for_manager(self):
        """Test Certificate Managers see all requests."""
        manager = UserFactory()
        manager.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
        manager.profile.save()

        other_user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=other_user)

        PendingCertificateRequestFactory(ca=ca, requested_by=manager)
        PendingCertificateRequestFactory(ca=ca, requested_by=other_user)

        requests = get_pending_requests_for_user(manager)

        assert requests.count() == 2

    def test_get_certificates_without_profile(self):
        """Test queryset returns empty for user without profile."""
        user = User.objects.create_user(
            username='noprofile',
            email='noprofile@example.com',
            password='test123'
        )
        user.profile.delete()

        certs = get_certificates_for_user(user)
        assert certs.count() == 0

    def test_get_pending_requests_without_profile(self):
        """Test queryset returns empty for user without profile."""
        user = User.objects.create_user(
            username='noprofile',
            email='noprofile@example.com',
            password='test123'
        )
        user.profile.delete()

        requests = get_pending_requests_for_user(user)
        assert requests.count() == 0


@pytest.mark.django_db
class TestPermissionMixins:
    """Tests for permission mixin classes."""

    def test_super_admin_required_mixin_allows_super_admin(self):
        """Test SuperAdminRequiredMixin allows Super Admin access."""
        user = UserFactory()
        user.profile.role = UserProfile.Role.SUPER_ADMIN
        user.profile.save()

        factory = RequestFactory()
        request = factory.get('/test/')
        request.user = user

        class TestView(SuperAdminRequiredMixin):
            def get(self, request):
                return 'OK'

        view = TestView()
        # dispatch would normally call LoginRequiredMixin first, so we test the role check
        assert user.profile.role in view.required_roles

    def test_super_admin_required_mixin_denies_admin(self):
        """Test SuperAdminRequiredMixin denies Administrator access."""
        user = UserFactory()
        user.profile.role = UserProfile.Role.ADMINISTRATOR
        user.profile.save()

        class TestView(SuperAdminRequiredMixin):
            pass

        view = TestView()
        assert user.profile.role not in view.required_roles

    def test_admin_or_super_admin_mixin_roles(self):
        """Test AdminOrSuperAdminRequiredMixin accepts correct roles."""
        mixin = AdminOrSuperAdminRequiredMixin()
        assert 'super_admin' in mixin.required_roles
        assert 'administrator' in mixin.required_roles
        assert 'certificate_manager' not in mixin.required_roles

    def test_can_manage_certificates_mixin_roles(self):
        """Test CanManageCertificatesMixin accepts correct roles."""
        mixin = CanManageCertificatesMixin()
        assert 'super_admin' in mixin.required_roles
        assert 'administrator' in mixin.required_roles
        assert 'certificate_manager' in mixin.required_roles
        assert 'certificate_requester' not in mixin.required_roles

    def test_can_view_audit_log_mixin_roles(self):
        """Test CanViewAuditLogMixin accepts correct roles."""
        mixin = CanViewAuditLogMixin()
        assert 'super_admin' in mixin.required_roles
        assert 'administrator' in mixin.required_roles
        assert 'certificate_manager' in mixin.required_roles
        assert 'auditor' in mixin.required_roles
        assert 'certificate_requester' not in mixin.required_roles
