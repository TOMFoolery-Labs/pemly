"""
API authentication backends for REST API access.
"""

import hashlib
import logging
import secrets
from datetime import timedelta

from django.utils import timezone
from rest_framework import authentication, exceptions

from .models import APIKey, AuditLog
from .utils import get_client_ip

logger = logging.getLogger(__name__)

# Must match APIKey.prefix (max_length=8).
PREFIX_LENGTH = 8
FAILURE_ROW_INTERVAL = timedelta(seconds=60)


class APIKeyAuthentication(authentication.BaseAuthentication):
    """
    Custom API key authentication for REST API.

    Expects API key in the Authorization header:
        Authorization: ApiKey <key>

    Format: pemly_<prefix>_<secret>
    """

    def authenticate(self, request):
        """
        Authenticate the request using API key.

        Returns:
            tuple: (user, api_key) if authentication succeeds
            None: if authentication should be skipped (no API key provided)

        Raises:
            AuthenticationFailed: if authentication fails
        """
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')

        if not auth_header.startswith('ApiKey '):
            # No API key provided, skip this authentication method
            return None

        api_key = auth_header[len('ApiKey '):].strip()

        # Keys look like pemly_<8-char prefix>_<secret>. Both parts are
        # token_urlsafe output, whose alphabet includes '_', so splitting on
        # underscores rejected roughly half of every key ever issued as
        # malformed. The prefix is fixed-width, so parse by position instead.
        head = 'pemly_'
        if not api_key.startswith(head) or len(api_key) < len(head) + PREFIX_LENGTH + 2 \
                or api_key[len(head) + PREFIX_LENGTH] != '_':
            self._record_failure(request, prefix='', reason='malformed key')
            raise exceptions.AuthenticationFailed('Invalid API key format')

        prefix = api_key[len(head):len(head) + PREFIX_LENGTH]
        secret = api_key[len(head) + PREFIX_LENGTH + 1:]

        try:
            key_obj = APIKey.objects.select_related('user').get(
                prefix=prefix,
                hashed_key=hash_api_key(secret),
            )
        except APIKey.DoesNotExist:
            self._record_failure(request, prefix=prefix, reason='no such key')
            raise exceptions.AuthenticationFailed('Invalid API key')

        if not key_obj.is_valid:
            self._record_failure(request, prefix=prefix, reason='inactive or expired')
            raise exceptions.AuthenticationFailed('API key is inactive or expired')

        key_obj.mark_used()
        return (key_obj.user, key_obj)

    def _record_failure(self, request, prefix: str, reason: str) -> None:
        """Audit a rejected key. Only the public prefix is recorded, never the key.

        Collapsed to one row per address per interval: the point is to see that
        probing is happening, not to let the prober write a row per request
        until the audit table fills the disk. A failed insert must not turn the
        intended 401 into a 500.
        """
        ip_address = get_client_ip(request)
        try:
            recent = AuditLog.objects.filter(
                action=AuditLog.Action.API_KEY_AUTH_FAILED,
                ip_address=ip_address,
                timestamp__gte=timezone.now() - FAILURE_ROW_INTERVAL,
            ).exists()
            if recent:
                return
            AuditLog.log(
                action=AuditLog.Action.API_KEY_AUTH_FAILED,
                resource_type='api_key',
                resource_name=prefix[:PREFIX_LENGTH],
                user=None,
                details={'prefix': prefix[:PREFIX_LENGTH], 'reason': reason},
                ip_address=ip_address,
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
            )
        except Exception:
            logger.exception("Could not write API key failure audit entry")


def generate_api_key():
    """
    Generate a new API key.

    Returns:
        tuple: (full_key, prefix, hashed_key)
            - full_key: The complete key to show to the user (only shown once)
            - prefix: The visible prefix for identification
            - hashed_key: The hashed secret for secure storage
    """
    # The prefix is hex so it can never contain the '_' separator; the secret
    # may, since authenticate() parses the prefix by width rather than by
    # splitting.
    prefix = secrets.token_hex(PREFIX_LENGTH // 2)
    secret = secrets.token_urlsafe(32)

    # Create the full key
    full_key = f"pemly_{prefix}_{secret}"

    # Hash the secret for storage
    hashed_key = hash_api_key(secret)

    return (full_key, prefix, hashed_key)


def hash_api_key(key: str) -> str:
    """
    Hash an API key for secure storage.

    Args:
        key: The API key secret to hash

    Returns:
        str: Hexadecimal hash of the key
    """
    return hashlib.sha256(key.encode()).hexdigest()
