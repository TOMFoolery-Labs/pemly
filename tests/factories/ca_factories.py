"""
CertificateAuthority factory for testing.
"""

import uuid
from datetime import timedelta

import factory
from django.utils import timezone

from core.models import CertificateAuthority, CAType, CAStatus, KeyAlgorithm
from tests.factories.user_factories import UserFactory


# Sample PEM certificate for testing (self-signed, not for production use)
SAMPLE_CA_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0GCSqGSIb3Qw0LBaAwYjELMAkGA1UE
BhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdp
ZGdpdHMgUHR5IEx0ZDEbMBkGA1UEAwwSVGVzdCBDZXJ0aWZpY2F0ZSBDQTAEHD0y
NDA2MTAxMDAwMDBaFw0zNDA2MDgxMDAwMDBaMGIxCzAJBgNVBAYTAlVTMRMwEQYD
VQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBM
dGQxGzAZBgNVBAMMElRlc3QgQ2VydGlmaWNhdGUgQ0EwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDN0LQcCX2LWk/HqCyP0HM+x6Hw/PQI0JwKlZF5hEiV
hGfA7xJIlDRZqLWIlxZJ6ZnIAxc6Y0wU9P1l8L7qOsn8HiGG0zLvqJKrVvC8BZJL
C3OZ3AJlKZH7uGa6HlCJ1l2n7UxaKSnVJVJHq3D+2Y0LDLPjGLBo3qB7C7MrQLpm
UH+AJf2dDqPvYrDnPB1KhBBZXJxSiQLBSwT2h8JJL7BYVpcLJiCL9L7G0FXBN02E
W3JzMOBL7YK+aIi1+BjC7ImTLBFB9AZYpAM8TT0qLpLuT0l9BJQN8iCBJfRgPayl
nNd7E9BBYMnKl1vLUwm9F2OkMLD4F9siBBpKg0TI2e9lAgMBAAGjUDBOMB0GA1Ud
DgQWBBRKPl2MfQX6+Gb0yWQ8jyYj9OHiJjAfBgNVHSMEGDAWgBRKPl2MfQX6+Gb0
yWQ8jyYj9OHiJjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCRFaXk
YPVMA6u5hyNLAFHB/hSCPvDLT5RFVABcJi9OSzSlJBmPfHvUaLOYPPMF4wBhfYhe
lpJP2gJqTBPkH8DxA6b/2HPsHiGGHeZbzCTdmfWwLZcfj8/r0YPBpRNxZvJNVLAg
p2TLbguaxHqYpgC6A8g7BR8sQLqj5nvGzO3RZJs7du3Qaj1FCL9Lbj4tYcfqNgRC
hLJkhF8Z1dPzfNiC76p1X7ALCje1E5Mr/F0mPFhJvLDfjgfHClf1z0Y5C8AKfWDd
2eRWABfIltYE8trirZ5aTMF0aML4u3pFC6eMSTlg0fxtBaJi2DWN+y0MfacnhKDd
o5nYyY1FzAWa5m3x
-----END CERTIFICATE-----"""

# Sample encrypted private key (Fernet encrypted)
SAMPLE_ENCRYPTED_PRIVATE_KEY = (
    "gAAAAABmYXN0LXNhbXBsZS1lbmNyeXB0ZWQta2V5LWZvci10ZXN0aW5nLW9ubHk"
    "tc2VlLWNhX2ZhY3Rvcmllcy5weQ=="
)


class CertificateAuthorityFactory(factory.django.DjangoModelFactory):
    """Factory for creating CertificateAuthority instances."""

    class Meta:
        model = CertificateAuthority

    id = factory.LazyFunction(uuid.uuid4)
    name = factory.Sequence(lambda n: f'Test CA {n}')
    common_name = factory.LazyAttribute(lambda obj: obj.name)
    organization = 'Test Organization'
    organizational_unit = 'Test Unit'
    country = 'US'
    state = 'California'
    locality = 'San Francisco'

    ca_type = CAType.ROOT
    parent = None
    status = CAStatus.ACTIVE
    path_length = None

    key_algorithm = KeyAlgorithm.RSA
    key_size = 4096
    validity_years = 10

    # Certificate data - use sample PEM for testing
    certificate_pem = SAMPLE_CA_CERT_PEM
    private_key_pem_encrypted = ''  # Will be set via set_private_key
    public_key_pem = ''
    csr_pem = ''
    serial_number = factory.LazyFunction(lambda: uuid.uuid4().hex[:16])

    # Validity dates
    not_before = factory.LazyFunction(timezone.now)
    not_after = factory.LazyFunction(lambda: timezone.now() + timedelta(days=3650))

    is_active = True

    # Audit fields
    created_by = factory.SubFactory(UserFactory)

    @factory.post_generation
    def with_private_key(self, create, extracted, **kwargs):
        """Optionally set a mock encrypted private key."""
        if extracted:
            # Use a simple placeholder that won't actually decrypt
            # Real tests should mock the encryption/decryption
            self.private_key_pem_encrypted = SAMPLE_ENCRYPTED_PRIVATE_KEY
            if create:
                self.save()


class RootCAFactory(CertificateAuthorityFactory):
    """Factory specifically for Root CAs."""

    ca_type = CAType.ROOT
    parent = None
    name = factory.Sequence(lambda n: f'Root CA {n}')


class IntermediateCAFactory(CertificateAuthorityFactory):
    """Factory specifically for Intermediate CAs."""

    ca_type = CAType.INTERMEDIATE
    path_length = 0
    name = factory.Sequence(lambda n: f'Intermediate CA {n}')

    @factory.lazy_attribute
    def parent(self):
        """Create a parent Root CA if not provided."""
        return RootCAFactory()


class AirGappedCAFactory(CertificateAuthorityFactory):
    """Factory for air-gapped CAs (no private key)."""

    status = CAStatus.AIR_GAPPED
    private_key_pem_encrypted = ''
    name = factory.Sequence(lambda n: f'Air-Gapped CA {n}')

    @factory.lazy_attribute
    def key_removed_at(self):
        return timezone.now()


class PendingCAFactory(CertificateAuthorityFactory):
    """Factory for pending CAs (awaiting external signing)."""

    ca_type = CAType.INTERMEDIATE
    status = CAStatus.PENDING
    certificate_pem = ''
    csr_pem = '-----BEGIN CERTIFICATE REQUEST-----\nSAMPLE CSR\n-----END CERTIFICATE REQUEST-----'
    name = factory.Sequence(lambda n: f'Pending CA {n}')
