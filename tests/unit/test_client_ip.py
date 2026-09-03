"""
Tests for core.utils.get_client_ip.

Two bugs live here historically. Every deployment runs behind Traefik, which
means REMOTE_ADDR is the proxy's container address and every audit entry recorded
172.x.y.z instead of the client. And the previous implementations read the
*first* X-Forwarded-For hop, which is whatever the caller sent - so switching the
header on would have let anyone dictate the address in the audit log.
"""

import pytest
from django.test import RequestFactory, override_settings

from core.utils import get_client_ip


@pytest.fixture
def rf():
    return RequestFactory()


@override_settings(TRUST_X_FORWARDED_FOR=False)
def test_header_is_ignored_when_no_proxy_is_declared(rf):
    request = rf.get('/', HTTP_X_FORWARDED_FOR='1.2.3.4', REMOTE_ADDR='10.0.0.1')

    assert get_client_ip(request) == '10.0.0.1'


@override_settings(TRUST_X_FORWARDED_FOR=True)
def test_single_hop_is_the_client(rf):
    request = rf.get('/', HTTP_X_FORWARDED_FOR='203.0.113.7', REMOTE_ADDR='172.18.0.2')

    assert get_client_ip(request) == '203.0.113.7'


@override_settings(TRUST_X_FORWARDED_FOR=True)
def test_forged_prefix_cannot_win(rf):
    """The proxy appends; everything left of its entry came from the caller."""
    request = rf.get(
        '/',
        HTTP_X_FORWARDED_FOR='6.6.6.6, 7.7.7.7, 203.0.113.7',
        REMOTE_ADDR='172.18.0.2',
    )

    assert get_client_ip(request) == '203.0.113.7'


@override_settings(TRUST_X_FORWARDED_FOR=True)
@pytest.mark.parametrize('value', ['not-an-ip', '', '   ', '1.2.3.4.5', '<script>'])
def test_a_value_that_is_not_an_address_falls_back(rf, value):
    """AuditLog.ip_address is an inet column; garbage here would 500 the request."""
    request = rf.get('/', HTTP_X_FORWARDED_FOR=value, REMOTE_ADDR='172.18.0.2')

    assert get_client_ip(request) == '172.18.0.2'


@override_settings(TRUST_X_FORWARDED_FOR=True)
def test_ipv6_is_accepted(rf):
    request = rf.get('/', HTTP_X_FORWARDED_FOR='2001:db8::1', REMOTE_ADDR='172.18.0.2')

    assert get_client_ip(request) == '2001:db8::1'
