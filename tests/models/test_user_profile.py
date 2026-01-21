"""
Tests for UserProfile model.
"""

import pytest
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

from accounts.models import UserProfile
from tests.factories import UserFactory


@pytest.mark.django_db
class TestUserProfileModel:
    """Tests for UserProfile model basic functionality."""

    def test_profile_created_on_user_creation(self):
        """Test that UserProfile is auto-created when User is created."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        assert hasattr(user, 'profile')
        assert user.profile.role == UserProfile.Role.CERTIFICATE_REQUESTER

    def test_first_superuser_gets_super_admin_role(self):
        """Test that the first superuser automatically gets Super Admin role."""
        # Clear any existing users first
        User.objects.all().delete()

        user = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='adminpass123'
        )
        assert user.profile.role == UserProfile.Role.SUPER_ADMIN

    def test_profile_str_representation(self):
        """Test string representation of UserProfile."""
        user = UserFactory(username='testuser')
        user.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
        user.profile.save()

        assert 'testuser' in str(user.profile)
        assert 'Certificate Manager' in str(user.profile)


@pytest.mark.django_db
class TestUserProfilePermissions:
    """Tests for UserProfile permission methods."""

    def test_super_admin_permissions(self):
        """Test Super Admin has all permissions."""
        user = UserFactory()
        user.profile.role = UserProfile.Role.SUPER_ADMIN
        user.profile.save()

        profile = user.profile
        assert profile.can_manage_users() is True
        assert profile.can_manage_cas() is True
        assert profile.can_manage_settings() is True
        assert profile.can_issue_certificates() is True
        assert profile.can_revoke_certificates() is True
        assert profile.can_approve_requests() is True
        assert profile.can_view_audit_log() is True
        assert profile.can_view_all_certificates() is True
        assert profile.is_read_only() is False

    def test_administrator_permissions(self):
        """Test Administrator permissions."""
        user = UserFactory()
        user.profile.role = UserProfile.Role.ADMINISTRATOR
        user.profile.save()

        profile = user.profile
        assert profile.can_manage_users() is False
        assert profile.can_manage_cas() is True
        assert profile.can_manage_settings() is True
        assert profile.can_issue_certificates() is True
        assert profile.can_revoke_certificates() is True
        assert profile.can_approve_requests() is True
        assert profile.can_view_audit_log() is True
        assert profile.can_view_all_certificates() is True
        assert profile.is_read_only() is False

    def test_certificate_manager_permissions(self):
        """Test Certificate Manager permissions."""
        user = UserFactory()
        user.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
        user.profile.save()

        profile = user.profile
        assert profile.can_manage_users() is False
        assert profile.can_manage_cas() is False
        assert profile.can_manage_settings() is False
        assert profile.can_issue_certificates() is True
        assert profile.can_revoke_certificates() is True
        assert profile.can_approve_requests() is True
        assert profile.can_view_audit_log() is True
        assert profile.can_view_all_certificates() is True
        assert profile.is_read_only() is False

    def test_certificate_requester_permissions(self):
        """Test Certificate Requester permissions (most restricted)."""
        user = UserFactory()
        user.profile.role = UserProfile.Role.CERTIFICATE_REQUESTER
        user.profile.save()

        profile = user.profile
        assert profile.can_manage_users() is False
        assert profile.can_manage_cas() is False
        assert profile.can_manage_settings() is False
        assert profile.can_issue_certificates() is False
        assert profile.can_revoke_certificates() is False
        assert profile.can_approve_requests() is False
        assert profile.can_view_audit_log() is False
        assert profile.can_view_all_certificates() is False
        assert profile.is_read_only() is False

    def test_auditor_permissions(self):
        """Test Auditor permissions (read-only)."""
        user = UserFactory()
        user.profile.role = UserProfile.Role.AUDITOR
        user.profile.save()

        profile = user.profile
        assert profile.can_manage_users() is False
        assert profile.can_manage_cas() is False
        assert profile.can_manage_settings() is False
        assert profile.can_issue_certificates() is False
        assert profile.can_revoke_certificates() is False
        assert profile.can_approve_requests() is False
        assert profile.can_view_audit_log() is True
        assert profile.can_view_all_certificates() is True
        assert profile.is_read_only() is True


@pytest.mark.django_db
class TestSuperAdminLimit:
    """Tests for Super Admin limit enforcement (max 2)."""

    def test_max_two_super_admins_enforced(self):
        """Test that creating more than 2 Super Admins raises validation error."""
        # Create first two Super Admins
        user1 = UserFactory()
        user1.profile.role = UserProfile.Role.SUPER_ADMIN
        user1.profile.save()

        user2 = UserFactory()
        user2.profile.role = UserProfile.Role.SUPER_ADMIN
        user2.profile.save()

        # Third should fail
        user3 = UserFactory()
        user3.profile.role = UserProfile.Role.SUPER_ADMIN

        with pytest.raises(ValidationError, match="Cannot create more than 2 Super Admin"):
            user3.profile.save()

    def test_can_change_role_to_super_admin_when_under_limit(self):
        """Test role change to Super Admin allowed when under limit."""
        user = UserFactory()
        can_change, reason = UserProfile.can_change_role(user, UserProfile.Role.SUPER_ADMIN)

        assert can_change is True
        assert reason == ''

    def test_cannot_change_role_to_super_admin_when_at_limit(self):
        """Test role change to Super Admin blocked when at limit."""
        # Create two Super Admins
        user1 = UserFactory()
        user1.profile.role = UserProfile.Role.SUPER_ADMIN
        user1.profile.save()

        user2 = UserFactory()
        user2.profile.role = UserProfile.Role.SUPER_ADMIN
        user2.profile.save()

        # Try to promote a third
        user3 = UserFactory()
        can_change, reason = UserProfile.can_change_role(user3, UserProfile.Role.SUPER_ADMIN)

        assert can_change is False
        assert 'Maximum 2 Super Admins' in reason


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
        assert 'Cannot delete the last Super Admin' in reason

    def test_can_delete_super_admin_when_multiple_exist(self):
        """Test Super Admin can be deleted when another exists."""
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

        can_change, reason = UserProfile.can_change_role(user, UserProfile.Role.ADMINISTRATOR)

        assert can_change is False
        assert 'Cannot demote the last Super Admin' in reason

    def test_can_demote_super_admin_when_multiple_exist(self):
        """Test Super Admin can be demoted when another exists."""
        user1 = UserFactory()
        user1.profile.role = UserProfile.Role.SUPER_ADMIN
        user1.profile.save()

        user2 = UserFactory()
        user2.profile.role = UserProfile.Role.SUPER_ADMIN
        user2.profile.save()

        can_change, reason = UserProfile.can_change_role(user1, UserProfile.Role.ADMINISTRATOR)

        assert can_change is True
        assert reason == ''

    def test_can_delete_non_super_admin(self):
        """Test non-Super Admin users can always be deleted."""
        user = UserFactory()
        user.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
        user.profile.save()

        can_delete, reason = UserProfile.can_delete_user(user)

        assert can_delete is True
        assert reason == ''

    def test_can_delete_user_without_profile(self):
        """Test user without profile can be deleted."""
        user = User.objects.create_user(
            username='noprofile',
            email='noprofile@example.com',
            password='test123'
        )
        # Delete the auto-created profile
        user.profile.delete()

        can_delete, reason = UserProfile.can_delete_user(user)

        assert can_delete is True
        assert reason == ''
