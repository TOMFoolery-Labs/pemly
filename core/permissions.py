"""
Permission mixins and helpers for role-based access control.

This module provides reusable permission mixins for class-based views
and helper functions for checking user permissions throughout the application.
"""

from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db.models import QuerySet

from core.models import Certificate, PendingCertificateRequest


class AuthenticatedRoleMixin(LoginRequiredMixin):
    """
    Base for every role check: resolve authentication before authorisation.

    Role checks read request.user.profile, which AnonymousUser does not have.
    Running them first turns "you are not logged in" into a 403, which is both
    the wrong status and a dead end for the user - the session simply needs
    renewing. That is exactly what happens after changing your own password:
    the session auth hash rotates, the next request is anonymous, and the user
    is met with Forbidden instead of the login page.

    Subclasses implement check_role() and can assume an authenticated user with
    a profile.
    """

    def check_role(self, request):
        """Raise PermissionDenied if the authenticated user may not proceed."""
        raise NotImplementedError

    def dispatch(self, request, *args, **kwargs):
        # LoginRequiredMixin.handle_no_permission() redirects to the login page
        # with ?next=, so the user lands back where they were going.
        if not request.user.is_authenticated:
            return self.handle_no_permission()

        if not hasattr(request.user, 'profile'):
            raise PermissionDenied("User has no profile")

        self.check_role(request)

        return super().dispatch(request, *args, **kwargs)


class RoleRequiredMixin(AuthenticatedRoleMixin):
    """
    Require specific role(s) to access a view.

    Usage:
        class MyView(RoleRequiredMixin, View):
            required_roles = ['super_admin', 'administrator']
    """
    required_roles = []  # Override in subclass

    def check_role(self, request):
        if request.user.profile.role not in self.required_roles:
            raise PermissionDenied(
                f"This page requires one of the following roles: {', '.join(self.required_roles)}"
            )


class SuperAdminRequiredMixin(RoleRequiredMixin):
    """Require Super Admin role to access view."""
    required_roles = ['super_admin']


class AdminOrSuperAdminRequiredMixin(RoleRequiredMixin):
    """Require Administrator or Super Admin role to access view."""
    required_roles = ['super_admin', 'administrator']


class CanManageCertificatesMixin(RoleRequiredMixin):
    """
    Require permission to manage certificates (issue, revoke).

    Allows: Super Admin, Administrator, Certificate Manager
    """
    required_roles = ['super_admin', 'administrator', 'certificate_manager']


class CanApproveCertificatesMixin(CanManageCertificatesMixin):
    """
    Require permission to approve certificate requests.

    Allows: Super Admin, Administrator, Certificate Manager
    This is an alias for CanManageCertificatesMixin.
    """
    pass


class CanViewAuditLogMixin(RoleRequiredMixin):
    """
    Require permission to view audit logs.

    Allows: Super Admin, Administrator, Certificate Manager, Auditor
    """
    required_roles = ['super_admin', 'administrator', 'certificate_manager', 'auditor']


class NotRequesterMixin(AuthenticatedRoleMixin):
    """
    Block Certificate Requesters from accessing a view.

    Allows: All roles except Certificate Requester
    """

    def check_role(self, request):
        if request.user.profile.role == 'certificate_requester':
            raise PermissionDenied(
                "Certificate Requesters do not have access to this page."
            )


class NotAuditorMixin(AuthenticatedRoleMixin):
    """
    Block Auditors from accessing a view (read-only users).

    Allows: All roles except Auditor
    """

    def check_role(self, request):
        if request.user.profile.is_read_only():
            raise PermissionDenied(
                "Auditors have read-only access and cannot perform this action."
            )


# Helper functions for use in views and templates

def user_can_manage_users(user) -> bool:
    """
    Check if user can create, edit, delete users and assign roles.

    Returns:
        True if user is a Super Admin
    """
    if not hasattr(user, 'profile'):
        return False
    return user.profile.can_manage_users()


def user_can_manage_cas(user) -> bool:
    """
    Check if user can create and configure Certificate Authorities.

    Returns:
        True if user is Super Admin or Administrator
    """
    if not hasattr(user, 'profile'):
        return False
    return user.profile.can_manage_cas()


def user_can_manage_settings(user) -> bool:
    """
    Check if user can modify application settings.

    Returns:
        True if user is Super Admin or Administrator
    """
    if not hasattr(user, 'profile'):
        return False
    return user.profile.can_manage_settings()


def user_can_issue_certificates(user) -> bool:
    """
    Check if user can issue certificates directly without approval.

    Returns:
        True if user is Super Admin, Administrator, or Certificate Manager
    """
    if not hasattr(user, 'profile'):
        return False
    return user.profile.can_issue_certificates()


def user_can_revoke_certificates(user) -> bool:
    """
    Check if user can revoke certificates.

    Returns:
        True if user is Super Admin, Administrator, or Certificate Manager
    """
    if not hasattr(user, 'profile'):
        return False
    return user.profile.can_revoke_certificates()


def user_can_approve_requests(user) -> bool:
    """
    Check if user can approve certificate requests from Requesters.

    Returns:
        True if user is Super Admin, Administrator, or Certificate Manager
    """
    if not hasattr(user, 'profile'):
        return False
    return user.profile.can_approve_requests()


def user_can_view_audit_log(user) -> bool:
    """
    Check if user can view audit logs.

    Returns:
        True if user is Super Admin, Administrator, Certificate Manager, or Auditor
    """
    if not hasattr(user, 'profile'):
        return False
    return user.profile.can_view_audit_log()


def user_can_view_all_certificates(user) -> bool:
    """
    Check if user can view all certificates (not just their own).

    Returns:
        True for all roles except Certificate Requester
    """
    if not hasattr(user, 'profile'):
        return False
    return user.profile.can_view_all_certificates()


def user_is_read_only(user) -> bool:
    """
    Check if user has read-only access (Auditor role).

    Returns:
        True if user is an Auditor
    """
    if not hasattr(user, 'profile'):
        return False
    return user.profile.is_read_only()


# Queryset filtering functions

def get_certificates_for_user(user) -> QuerySet[Certificate]:
    """
    Get certificates visible to this user based on their role.

    - Certificate Requesters: Only their own certificates
    - All other roles: All certificates

    Returns:
        Filtered queryset of Certificate objects
    """
    if not hasattr(user, 'profile'):
        # Fallback: return empty queryset if user has no profile
        return Certificate.objects.none()

    if user.profile.role == 'certificate_requester':
        # Requesters can only see certificates they created
        return Certificate.objects.filter(created_by=user)

    # All other roles can see all certificates
    return Certificate.objects.all()


def get_pending_requests_for_user(user) -> QuerySet[PendingCertificateRequest]:
    """
    Get pending certificate requests visible to this user based on their role.

    - Certificate Requesters: Only their own requests
    - Managers/Admins: All pending requests (for approval)
    - Auditors: All requests (read-only)

    Returns:
        Filtered queryset of PendingCertificateRequest objects
    """
    if not hasattr(user, 'profile'):
        return PendingCertificateRequest.objects.none()

    role = user.profile.role

    if role == 'certificate_requester':
        # Requesters can only see their own requests
        return PendingCertificateRequest.objects.filter(requested_by=user)

    # Managers, Admins, Auditors can see all requests
    return PendingCertificateRequest.objects.all()


def can_user_approve_request(user, request: PendingCertificateRequest) -> tuple[bool, str]:
    """
    Check if a user can approve a specific certificate request.

    Enforces separation of duties: users cannot approve their own requests.

    Returns:
        (can_approve, reason) tuple
    """
    if not hasattr(user, 'profile'):
        return (False, "User has no profile")

    # Check if user has approval permission
    if not user.profile.can_approve_requests():
        return (False, "You do not have permission to approve certificate requests")

    # Check if request is in pending status
    if not request.is_pending:
        return (False, f"Request is {request.get_status_display()}, not pending")

    # Enforce separation of duties: can't approve your own request
    if request.requested_by == user:
        return (False, "You cannot approve your own certificate request (separation of duties)")

    return (True, "")


# Context processor helpers

def add_permission_context(request):
    """
    Add permission-related context variables for use in templates.

    Add this to TEMPLATES['OPTIONS']['context_processors'] in settings.py:
        'core.permissions.add_permission_context'

    Usage in templates:
        {% if can_manage_users %}
            <a href="{% url 'accounts:user_list' %}">Users</a>
        {% endif %}
    """
    if not request.user.is_authenticated:
        return {}

    return {
        'can_manage_users': user_can_manage_users(request.user),
        'can_manage_cas': user_can_manage_cas(request.user),
        'can_manage_settings': user_can_manage_settings(request.user),
        'can_issue_certificates': user_can_issue_certificates(request.user),
        'can_revoke_certificates': user_can_revoke_certificates(request.user),
        'can_approve_requests': user_can_approve_requests(request.user),
        'can_view_audit_log': user_can_view_audit_log(request.user),
        'can_view_all_certificates': user_can_view_all_certificates(request.user),
        'is_read_only': user_is_read_only(request.user),
        'is_super_admin': hasattr(request.user, 'profile') and request.user.profile.role == 'super_admin',
    }
