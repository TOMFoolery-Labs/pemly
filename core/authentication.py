"""
API authentication backends for REST API access.
"""

import hashlib
import secrets

from rest_framework import authentication, exceptions

from .models import APIKey, AuditLog
from .utils import get_client_ip


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

        api_key = auth_header.replace('ApiKey ', '').strip()

        if not api_key.startswith('pemly_'):
            self._record_failure(request, prefix='', reason='malformed prefix')
            raise exceptions.AuthenticationFailed('Invalid API key format')

        try:
            # Split key into prefix and secret
            parts = api_key.split('_')
            if len(parts) != 3:
                self._record_failure(request, prefix='', reason='malformed key')
                raise exceptions.AuthenticationFailed('Invalid API key format')

            prefix = parts[1]
            secret = parts[2]

            # Hash the secret to compare with stored hash
            hashed_secret = hash_api_key(secret)

            # Look up the API key by prefix
            key_obj = APIKey.objects.select_related('user').get(
                prefix=prefix,
                hashed_key=hashed_secret
            )

            if not key_obj.is_valid:
                self._record_failure(request, prefix=prefix, reason='inactive or expired')
                raise exceptions.AuthenticationFailed('API key is inactive or expired')

            # Update last used timestamp
            key_obj.mark_used()

            return (key_obj.user, key_obj)

        except APIKey.DoesNotExist:
            self._record_failure(request, prefix=prefix, reason='no such key')
            raise exceptions.AuthenticationFailed('Invalid API key')

    def _record_failure(self, request, prefix: str, reason: str) -> None:
        """Audit a rejected key. Only the public prefix is recorded, never the key."""
        AuditLog.log(
            action=AuditLog.Action.API_KEY_AUTH_FAILED,
            resource_type='api_key',
            resource_name=prefix[:255],
            user=None,
            details={'prefix': prefix[:8], 'reason': reason},
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
        )


def generate_api_key():
    """
    Generate a new API key.

    Returns:
        tuple: (full_key, prefix, hashed_key)
            - full_key: The complete key to show to the user (only shown once)
            - prefix: The visible prefix for identification
            - hashed_key: The hashed secret for secure storage
    """
    # Generate random prefix and secret
    prefix = secrets.token_urlsafe(6)[:8]
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
