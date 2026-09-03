"""
Login throttling.

Failures are counted straight out of the audit log: one source of truth, shared
by every gunicorn worker, surviving restarts, and visible to an auditor rather
than only to a rate limiter.

The lock is keyed on the (username, address) *pair*. Keying on the username
alone - the first version of this - let anyone who knew an operator's username
keep them locked out of the CA console from anywhere, indefinitely, by sending
ten bad passwords every fourteen minutes. A pair lock means an attacker locks
out only their own address. A much looser per-address limit still catches
spraying many usernames from one place.

Enforcement lives in accounts.backends.ThrottledModelBackend, so it covers every
path that ends in authenticate(): /accounts/login/, /admin/login/, and DRF's
session authentication. Recording lives in accounts.signals, for the same reason.
"""

import logging
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from core.models import AuditLog

logger = logging.getLogger(__name__)

# Once a pair is locked, refused attempts are collapsed to one audit row per
# this interval. The throttle stops password checks; this stops an attacker
# turning every refused request into a row and filling the database with them.
BLOCKED_ROW_INTERVAL = timedelta(seconds=60)


def _window_start():
    return timezone.now() - timedelta(minutes=settings.LOGIN_FAILURE_WINDOW_MINUTES)


def _pair_failures(username: str, ip_address: str | None, since) -> int:
    """Failures for this pair, ignoring anything before the user's last success.

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
    if last_success:
        since = last_success

    return AuditLog.objects.filter(
        action=AuditLog.Action.USER_LOGIN_FAILED,
        resource_name=username,
        ip_address=ip_address,
        timestamp__gte=since,
    ).count()


def is_throttled(username: str, ip_address: str | None) -> bool:
    """Whether an attempt from this pair should be refused before any password check."""
    since = _window_start()

    if username and settings.LOGIN_FAILURE_LIMIT:
        if _pair_failures(username, ip_address, since) >= settings.LOGIN_FAILURE_LIMIT:
            return True

    if ip_address and settings.LOGIN_FAILURE_LIMIT_PER_IP:
        ip_failures = AuditLog.objects.filter(
            action=AuditLog.Action.USER_LOGIN_FAILED,
            ip_address=ip_address,
            timestamp__gte=since,
        ).count()
        if ip_failures >= settings.LOGIN_FAILURE_LIMIT_PER_IP:
            return True

    return False


def _write(action, username: str, ip_address: str | None, user_agent: str, details: dict) -> None:
    # A failed audit insert must not turn a refused login into a 500: the
    # refusal already happened, and the attacker gains nothing from the error.
    try:
        AuditLog.log(
            action=action,
            resource_type='user',
            resource_name=username[:255],
            user=None,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent[:500],
        )
    except Exception:
        logger.exception("Could not write %s audit entry for %r", action, username[:255])


def record_failure(username: str, ip_address: str | None, user_agent: str = '') -> None:
    """Record a rejected password. The submitted password is never stored."""
    _write(
        AuditLog.Action.USER_LOGIN_FAILED,
        username, ip_address, user_agent,
        {'username': username[:255]},
    )


def record_blocked(username: str, ip_address: str | None, user_agent: str = '') -> None:
    """Record an attempt refused by the throttle, at most once per interval per pair."""
    recent = AuditLog.objects.filter(
        action=AuditLog.Action.USER_LOGIN_BLOCKED,
        resource_name=username[:255],
        ip_address=ip_address,
        timestamp__gte=timezone.now() - BLOCKED_ROW_INTERVAL,
    ).exists()
    if recent:
        return

    _write(
        AuditLog.Action.USER_LOGIN_BLOCKED,
        username, ip_address, user_agent,
        {'username': username[:255], 'window_minutes': settings.LOGIN_FAILURE_WINDOW_MINUTES},
    )
