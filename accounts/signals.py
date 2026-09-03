"""
Audit every login outcome, whichever view produced it.

Django fires these from authenticate() and login()/logout() themselves, so the
admin site and DRF are covered without touching them. LoginView used to write
the success row itself and nothing wrote the failure row at all.
"""

from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from accounts.throttling import is_throttled, record_blocked, record_failure
from core.models import AuditLog
from core.utils import get_client_ip


def _user_agent(request) -> str:
    return request.META.get('HTTP_USER_AGENT', '')[:500]


@receiver(user_login_failed)
def audit_login_failed(sender, credentials, request, **kwargs):
    if request is None:
        return
    username = (credentials.get('username') or '').strip()
    ip_address = get_client_ip(request)

    # The backend has already refused this attempt if the pair is throttled, and
    # no rows have been written since it decided, so the same check tells us
    # which kind of refusal this was.
    if is_throttled(username, ip_address):
        record_blocked(username, ip_address, _user_agent(request))
    else:
        record_failure(username, ip_address, _user_agent(request))


@receiver(user_logged_in)
def audit_login(sender, request, user, **kwargs):
    AuditLog.log(
        action=AuditLog.Action.USER_LOGIN,
        resource_type='user',
        resource_name=user.username,
        user=user,
        ip_address=get_client_ip(request),
        user_agent=_user_agent(request),
    )


@receiver(user_logged_out)
def audit_logout(sender, request, user, **kwargs):
    if user is None:
        return
    AuditLog.log(
        action=AuditLog.Action.USER_LOGOUT,
        resource_type='user',
        resource_name=user.username,
        user=user,
        ip_address=get_client_ip(request),
        user_agent=_user_agent(request),
    )
