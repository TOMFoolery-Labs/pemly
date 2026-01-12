from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver


class UserProfile(models.Model):
    """
    User profile with role-based access control.

    Each user has exactly one role that determines their permissions:
    - Super Admin: Full system access including user management (max 2)
    - Administrator: Full access except user management
    - Certificate Manager: Issue/revoke/approve certificates, view audit logs
    - Certificate Requester: Submit requests, view only own certificates
    - Auditor: Read-only access to certificates, CAs, and audit logs
    """

    class Role(models.TextChoices):
        SUPER_ADMIN = 'super_admin', 'Super Admin'
        ADMINISTRATOR = 'administrator', 'Administrator'
        CERTIFICATE_MANAGER = 'certificate_manager', 'Certificate Manager'
        CERTIFICATE_REQUESTER = 'certificate_requester', 'Certificate Requester'
        AUDITOR = 'auditor', 'Auditor'

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile',
        help_text="The user this profile belongs to"
    )
    role = models.CharField(
        max_length=30,
        choices=Role.choices,
        default=Role.CERTIFICATE_REQUESTER,
        help_text="The user's role determines their permissions"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"

    def __str__(self):
        return f"{self.user.username} ({self.get_role_display()})"

    def clean(self):
        """Validate Super Admin limit before saving."""
        if self.role == self.Role.SUPER_ADMIN:
            # Get count of existing Super Admins (excluding this profile if updating)
            existing_super_admins = UserProfile.objects.filter(
                role=self.Role.SUPER_ADMIN
            ).exclude(pk=self.pk).count()

            if existing_super_admins >= 2:
                raise ValidationError(
                    "Cannot create more than 2 Super Admin users. "
                    "This is a security requirement for PKI operations."
                )

    def save(self, *args, **kwargs):
        """Enforce validation before saving."""
        self.full_clean()
        super().save(*args, **kwargs)

    # Permission helper methods

    def can_manage_users(self) -> bool:
        """Can create, edit, delete users and assign roles."""
        return self.role == self.Role.SUPER_ADMIN

    def can_manage_cas(self) -> bool:
        """Can create and configure Certificate Authorities."""
        return self.role in [self.Role.SUPER_ADMIN, self.Role.ADMINISTRATOR]

    def can_manage_settings(self) -> bool:
        """Can modify application settings."""
        return self.role in [self.Role.SUPER_ADMIN, self.Role.ADMINISTRATOR]

    def can_issue_certificates(self) -> bool:
        """Can issue certificates directly without approval."""
        return self.role in [
            self.Role.SUPER_ADMIN,
            self.Role.ADMINISTRATOR,
            self.Role.CERTIFICATE_MANAGER
        ]

    def can_revoke_certificates(self) -> bool:
        """Can revoke certificates."""
        return self.role in [
            self.Role.SUPER_ADMIN,
            self.Role.ADMINISTRATOR,
            self.Role.CERTIFICATE_MANAGER
        ]

    def can_approve_requests(self) -> bool:
        """Can approve certificate requests from Requesters."""
        return self.role in [
            self.Role.SUPER_ADMIN,
            self.Role.ADMINISTRATOR,
            self.Role.CERTIFICATE_MANAGER
        ]

    def can_view_audit_log(self) -> bool:
        """Can view audit logs."""
        return self.role in [
            self.Role.SUPER_ADMIN,
            self.Role.ADMINISTRATOR,
            self.Role.CERTIFICATE_MANAGER,
            self.Role.AUDITOR
        ]

    def can_view_all_certificates(self) -> bool:
        """Can view all certificates (not just own)."""
        return self.role != self.Role.CERTIFICATE_REQUESTER

    def is_read_only(self) -> bool:
        """User has read-only access (Auditor role)."""
        return self.role == self.Role.AUDITOR

    @classmethod
    def can_delete_user(cls, user_to_delete) -> tuple[bool, str]:
        """
        Check if a user can be deleted.

        Returns:
            (can_delete, reason) tuple
        """
        try:
            profile = user_to_delete.profile
        except UserProfile.DoesNotExist:
            # User has no profile, can delete
            return (True, "")

        # Prevent deleting the last Super Admin
        if profile.role == cls.Role.SUPER_ADMIN:
            super_admin_count = cls.objects.filter(role=cls.Role.SUPER_ADMIN).count()
            if super_admin_count <= 1:
                return (
                    False,
                    "Cannot delete the last Super Admin user. Create another Super Admin first."
                )

        return (True, "")

    @classmethod
    def can_change_role(cls, user, new_role: str) -> tuple[bool, str]:
        """
        Check if a user's role can be changed.

        Returns:
            (can_change, reason) tuple
        """
        try:
            profile = user.profile
        except UserProfile.DoesNotExist:
            # User has no profile, can create one with any role
            if new_role == cls.Role.SUPER_ADMIN:
                existing_super_admins = cls.objects.filter(role=cls.Role.SUPER_ADMIN).count()
                if existing_super_admins >= 2:
                    return (False, "Maximum 2 Super Admins allowed")
            return (True, "")

        old_role = profile.role

        # Check if demoting the last Super Admin
        if old_role == cls.Role.SUPER_ADMIN and new_role != cls.Role.SUPER_ADMIN:
            super_admin_count = cls.objects.filter(role=cls.Role.SUPER_ADMIN).count()
            if super_admin_count <= 1:
                return (
                    False,
                    "Cannot demote the last Super Admin. Create another Super Admin first."
                )

        # Check if promoting to Super Admin would exceed limit
        if new_role == cls.Role.SUPER_ADMIN and old_role != cls.Role.SUPER_ADMIN:
            super_admin_count = cls.objects.filter(role=cls.Role.SUPER_ADMIN).count()
            if super_admin_count >= 2:
                return (False, "Maximum 2 Super Admins allowed")

        return (True, "")


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Automatically create a UserProfile when a User is created."""
    if created:
        # Check if this is the first user (likely via createsuperuser)
        user_count = User.objects.count()

        # If this is the first user and they're a superuser, make them Super Admin
        if user_count == 1 and instance.is_superuser:
            role = UserProfile.Role.SUPER_ADMIN
        # If they're a superuser and we have <2 Super Admins, make them Super Admin
        elif instance.is_superuser:
            existing_super_admins = UserProfile.objects.filter(
                role=UserProfile.Role.SUPER_ADMIN
            ).count()
            if existing_super_admins < 2:
                role = UserProfile.Role.SUPER_ADMIN
            else:
                role = UserProfile.Role.ADMINISTRATOR
        else:
            # Default role for non-superusers
            role = UserProfile.Role.CERTIFICATE_REQUESTER

        UserProfile.objects.create(user=instance, role=role)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Save the profile when the user is saved."""
    # Only save if profile exists (not during creation)
    if hasattr(instance, 'profile'):
        instance.profile.save()
