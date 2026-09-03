"""
Shared request helpers.
"""

import ipaddress

from django.conf import settings


def get_client_ip(request) -> str | None:
    """Return the address of the client that made this request.

    X-Forwarded-For is only consulted when TRUST_X_FORWARDED_FOR says the app
    runs behind a proxy that sets it; otherwise any client could dictate the
    address recorded in the audit log.

    Even then, the header is a chain and only its final hop is written by our own
    proxy - everything to the left of that was supplied by the caller. Reading
    the last entry therefore holds whether the proxy replaces the header or
    appends to a chain the client invented. The value is validated as an IP
    address before use: with TRUST_X_FORWARDED_FOR enabled but no proxy actually
    in front, the header is attacker-controlled, and AuditLog.ip_address is an
    inet column that rejects anything else.
    """
    if getattr(settings, 'TRUST_X_FORWARDED_FOR', False):
        forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
        if forwarded:
            candidate = forwarded.split(',')[-1].strip()
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                pass
            else:
                return candidate

    return request.META.get('REMOTE_ADDR')
