"""
Login throttling.

Repeated password guessing against a certificate authority console was neither
limited nor recorded: LoginView logged only successes, so a failed attempt left
no trace at all, and nothing slowed one attempt down.

Failures are counted straight out of the audit log. That keeps one source of
truth - an auditor sees every rejected attempt, and the count is shared by all
gunicorn workers and survives a restart, which a per-process cache would not be.
"""

from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from core.models import AuditLog


def _window_start():
    minutes = getattr(settings, 'LOGIN_FAILURE_WINDOW_MINUTES', 15)
    return timezone.now() - timedelta(minutes=minutes)


def _failures_since_last_success(username: str, since):
    """Count this username's failures, ignoring anything before its last success.

    A successful sign-in clears the slate: someone who mistypes a password four
    times and then gets it right should not be four failures closer to a lockout
    for the rest of the window.
    """
    last_success = (
        AuditLog.objects
        .filter(action=AuditLog.Action.USER_LOGIN, resource_name=username, timestamp__gte=since)
        .order_by('-timestamp')
        .values_list('timestamp', flat=True)
        .first()
    )
    start = max(since, last_success) if last_success else since

    return AuditLog.objects.filter(
        action=AuditLog.Action.USER_LOGIN_FAILED,
        resource_name=username,
        timestamp__gte=start,
    ).count()


def login_is_throttled(username: str, ip_address: str | None) -> bool:
    """Whether this attempt should be refused before any password is checked."""
    since = _window_start()

    if username:
        limit = getattr(settings, 'LOGIN_FAILURE_LIMIT', 10)
        if limit and _failures_since_last_success(username, since) >= limit:
            return True

    if ip_address:
        ip_limit = getattr(settings, 'LOGIN_FAILURE_LIMIT_PER_IP', 50)
        if ip_limit:
            ip_failures = AuditLog.objects.filter(
                action=AuditLog.Action.USER_LOGIN_FAILED,
                ip_address=ip_address,
                timestamp__gte=since,
            ).count()
            if ip_failures >= ip_limit:
                return True

    return False


def record_login_failure(username: str, ip_address: str | None, user_agent: str) -> None:
    """Record a rejected password. The submitted password is never stored."""
    AuditLog.log(
        action=AuditLog.Action.USER_LOGIN_FAILED,
        resource_type='user',
        resource_name=username[:255],
        user=None,
        details={'username': username[:255]},
        ip_address=ip_address,
        user_agent=user_agent,
    )


def record_login_blocked(username: str, ip_address: str | None, user_agent: str) -> None:
    """Record an attempt refused by the throttle rather than by a bad password."""
    AuditLog.log(
        action=AuditLog.Action.USER_LOGIN_BLOCKED,
        resource_type='user',
        resource_name=username[:255],
        user=None,
        details={
            'username': username[:255],
            'window_minutes': getattr(settings, 'LOGIN_FAILURE_WINDOW_MINUTES', 15),
        },
        ip_address=ip_address,
        user_agent=user_agent,
    )
