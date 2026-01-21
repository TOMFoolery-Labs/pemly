"""
Certificate and PendingCertificateRequest factories for testing.
"""

import uuid
from datetime import timedelta

import factory
from django.utils import timezone

from core.models import (
    Certificate,
    PendingCertificateRequest,
    CertificateType,
    CertificateStatus,
    KeyAlgorithm,
    RevocationReason,
)
from tests.factories.ca_factories import CertificateAuthorityFactory
from tests.factories.user_factories import UserFactory


# Sample certificate PEM for testing
SAMPLE_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQxGzAZBgNVBAMMElRlc3QgQ2VydGlmaWNhdGUgQ0EwHhcN
MjQwNjEwMTAwMDAwWhcNMjUwNjEwMTAwMDAwWjBiMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkg
THRkMRswGQYDVQQDDBJ0ZXN0LmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAzdC0HAl9i1pPx6gsj9BzPseh8Pz0CNCcCpWReYRIlYRn
wO8SSJQ0Wai1iJcWSemZyAMXOmNMFPT9ZfC+6jrJ/B4hhtMy76iSq1bwvAWSSwtz
mdwCZSmR+7hmuh5QidZdp+1MWikp1SVSRqtw/tmNCwyz4xiwa96gewuzK0C6ZlB/
gCX9nQ6j72Kw5zwdSoQQWVycUokCwUsE9ofCSS+wWFaXCyYgi/S+xtBVwTdNhFty
czDgS+2CvmiItfgYwuyJkywRQfQGWKQDPE09Ki6S7k9JfQSUDfIggSX0YD2spZzX
exPQQWDJypdbyl0JvRdjpDCw+BfbIgQaSoNEyNnvZQIDAQABoyMwITAfBgNVHREE
GDAWhwR/AAABggp0ZXN0LmxvY2FsMA0GCSqGSIb3DQEBCwUAA4IBAQCRFaXkYPVM
A6u5hyNLAFHB/hSCPvDLT5RFVABcJi9OSzSlJBmPfHvUaLOYPPMF4wBhfYhelpJP
2gJqTBPkH8DxA6b/2HPsHiGGHeZbzCTdmfWwLZcfj8/r0YPBpRNxZvJNVLAgp2TL
bguaxHqYpgC6A8g7BR8sQLqj5nvGzO3RZJs7du3Qaj1FCL9Lbj4tcfqNgRChLJkh
F8Z1dPzfNiC76p1X7ALCje1E5Mr/F0mPFhJvLDfjgfHClf1z0Y5C8AKfWDd2eRWA
BfIltYE8trirZ5aTMF0aML4u3pFC6eMSTlg0fxtBaJi2DWN+y0MfacnhKDdo5nYy
Y1FzAWa5m3x
-----END CERTIFICATE-----"""

# Sample CSR PEM for testing
SAMPLE_CSR_PEM = """-----BEGIN CERTIFICATE REQUEST-----
MIICijCCAXICAQAwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAMWAmHLy1rhyhz3u7E3Y8L/+iDJDvDZHx9d8c8Gw
iF3JZLDd3zRDBFPzhH6YbVuBC7Jnqxzv7EDzmUYHOO3eoYzQZAq7P4u/G4v3EoVx
L4n7BIUJLq9LqNJiJAJl/F4V8zPvAP/i3h1tW/hH7H/qSxZCTOD3h4r3csCn0NJi
YjZ9Ld1Z7H4PkJZTJhP9n8YEOFnKgLv4gPGvOz6T3b9h8xqJhL7EJHJL0kHr1UAD
Cz9N7EATa3kPw2+IQp9JHYdLrNylA+PRhcLdcjBBi/jRdlGSN2HQL4q3p8wsHSFt
0gAR9qU6HsLE+EZdTvcz0+qp7J5KQMHO3z8qmHaJ8M7SYjUCAwEAAaAAMA0GCSqG
SIb3DQEBCwUAA4IBAQCYaKNc7GtCF/7d+SqA7FLVJlmA2nM/nP9PLFA7LvAyfQcN
xBGGIPnkBQCdMNfb44nULJiK7p3M7aBW3sFYAq/cBziH/eLiP7xJTYiVxBQdZPTg
qGP3h6lNDwLOk+J9d1/f0xpXfH5CbGJXO5mFJKLbO9b05gM9fGxjEz3pnwD5FWJK
1TfD7LbjHPWSPh3fHCNWOA9+lUZQDjCLuK8OB3F4VNDgJk2vRCth6oHQeevT8hFM
cJLUzAP0qg4/y5HZA3Sn5TnvcV8RB8C5h7h+/WFHMREJqb8qL7lW5MZXJKE5xgL6
nXqJxJFM3+ZiJdXj/nSrmK+i7bQx3/f2rq4D5jKL
-----END CERTIFICATE REQUEST-----"""


class CertificateFactory(factory.django.DjangoModelFactory):
    """Factory for creating Certificate instances."""

    class Meta:
        model = Certificate

    id = factory.LazyFunction(uuid.uuid4)
    ca = factory.SubFactory(CertificateAuthorityFactory)

    type = CertificateType.SERVER_TLS
    common_name = factory.Sequence(lambda n: f'test{n}.example.com')
    organization = 'Test Organization'

    san_dns_names = factory.LazyAttribute(lambda obj: [obj.common_name])
    san_ip_addresses = factory.LazyFunction(list)
    san_email_addresses = factory.LazyFunction(list)

    key_algorithm = KeyAlgorithm.RSA
    key_size = 2048
    validity_days = 365

    certificate_pem = SAMPLE_CERT_PEM
    private_key_pem_encrypted = ''
    public_key_pem = ''
    csr_pem = ''
    serial_number = factory.LazyFunction(lambda: uuid.uuid4().hex[:16])

    not_before = factory.LazyFunction(timezone.now)
    not_after = factory.LazyFunction(lambda: timezone.now() + timedelta(days=365))

    status = CertificateStatus.ACTIVE
    revoked_at = None
    revocation_reason = ''

    is_archived = False

    created_by = factory.SubFactory(UserFactory)


class ServerTLSCertificateFactory(CertificateFactory):
    """Factory for Server TLS certificates."""

    type = CertificateType.SERVER_TLS
    common_name = factory.Sequence(lambda n: f'server{n}.example.com')


class ClientAuthCertificateFactory(CertificateFactory):
    """Factory for Client Authentication certificates."""

    type = CertificateType.CLIENT_AUTH
    common_name = factory.Sequence(lambda n: f'client{n}@example.com')
    san_email_addresses = factory.LazyAttribute(lambda obj: [obj.common_name])


class EmailProtectionCertificateFactory(CertificateFactory):
    """Factory for Email Protection (S/MIME) certificates."""

    type = CertificateType.EMAIL_PROTECTION
    common_name = factory.Sequence(lambda n: f'email{n}@example.com')
    san_email_addresses = factory.LazyAttribute(lambda obj: [obj.common_name])


class RevokedCertificateFactory(CertificateFactory):
    """Factory for revoked certificates."""

    status = CertificateStatus.REVOKED
    revoked_at = factory.LazyFunction(timezone.now)
    revocation_reason = RevocationReason.UNSPECIFIED


class ExpiredCertificateFactory(CertificateFactory):
    """Factory for expired certificates."""

    status = CertificateStatus.EXPIRED
    not_before = factory.LazyFunction(lambda: timezone.now() - timedelta(days=730))
    not_after = factory.LazyFunction(lambda: timezone.now() - timedelta(days=365))


class ArchivedCertificateFactory(RevokedCertificateFactory):
    """Factory for archived (revoked + archived) certificates."""

    is_archived = True
    archived_at = factory.LazyFunction(timezone.now)
    archived_by = factory.SubFactory(UserFactory)


class PendingCertificateRequestFactory(factory.django.DjangoModelFactory):
    """Factory for creating PendingCertificateRequest instances."""

    class Meta:
        model = PendingCertificateRequest

    id = factory.LazyFunction(uuid.uuid4)
    ca = factory.SubFactory(CertificateAuthorityFactory)
    requested_by = factory.SubFactory(UserFactory)

    type = CertificateType.SERVER_TLS
    common_name = factory.Sequence(lambda n: f'request{n}.example.com')
    organization = 'Test Organization'

    san_dns_names = factory.LazyAttribute(lambda obj: [obj.common_name])
    san_ip_addresses = factory.LazyFunction(list)
    san_email_addresses = factory.LazyFunction(list)

    key_algorithm = KeyAlgorithm.RSA
    key_size = 2048
    validity_days = 365

    csr_pem = SAMPLE_CSR_PEM

    status = PendingCertificateRequest.Status.PENDING
    reviewed_by = None
    reviewed_at = None
    rejection_reason = ''
    issued_certificate = None


class ApprovedRequestFactory(PendingCertificateRequestFactory):
    """Factory for approved certificate requests."""

    status = PendingCertificateRequest.Status.APPROVED
    reviewed_by = factory.SubFactory(UserFactory)
    reviewed_at = factory.LazyFunction(timezone.now)


class RejectedRequestFactory(PendingCertificateRequestFactory):
    """Factory for rejected certificate requests."""

    status = PendingCertificateRequest.Status.REJECTED
    reviewed_by = factory.SubFactory(UserFactory)
    reviewed_at = factory.LazyFunction(timezone.now)
    rejection_reason = 'Request rejected for testing purposes'


class IssuedRequestFactory(PendingCertificateRequestFactory):
    """Factory for issued certificate requests."""

    status = PendingCertificateRequest.Status.ISSUED
    reviewed_by = factory.SubFactory(UserFactory)
    reviewed_at = factory.LazyFunction(timezone.now)
    issued_certificate = factory.SubFactory(CertificateFactory)
