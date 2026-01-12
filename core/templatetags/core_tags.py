"""
Template tags for core app.
"""

from django import template
from core.models import PendingCertificateRequest

register = template.Library()


@register.simple_tag
def pending_approvals_count():
    """
    Get the count of pending certificate requests awaiting approval.

    Used in navigation menu to show badge with pending count.
    """
    return PendingCertificateRequest.objects.filter(
        status=PendingCertificateRequest.Status.PENDING
    ).count()
