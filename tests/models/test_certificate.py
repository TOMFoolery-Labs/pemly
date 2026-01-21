"""
Tests for Certificate model.
"""

import pytest
from datetime import timedelta
from unittest.mock import patch

from django.conf import settings
from django.utils import timezone

from core.models import Certificate, CertificateStatus, RevocationReason
from tests.factories import (
    CertificateFactory,
    CertificateAuthorityFactory,
    UserFactory,
    RevokedCertificateFactory,
)


@pytest.mark.django_db
class TestCertificateModel:
    """Tests for Certificate model basic functionality."""

    def test_create_certificate(self):
        """Test creating a certificate."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)
        cert = CertificateFactory(
            ca=ca,
            common_name='test.example.com',
            type='server_tls',
            created_by=user,
        )

        assert cert.common_name == 'test.example.com'
        assert cert.type == 'server_tls'
        assert cert.ca == ca
        assert cert.status == CertificateStatus.ACTIVE

    def test_certificate_str_representation(self):
        """Test string representation of certificate."""
        cert = CertificateFactory(common_name='test.example.com', type='server_tls')
        assert 'test.example.com' in str(cert)
        assert 'Server TLS' in str(cert)

    def test_certificate_ordering(self):
        """Test certificates are ordered by created_at descending."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)

        cert1 = CertificateFactory(ca=ca, common_name='first.example.com', created_by=user)
        cert2 = CertificateFactory(ca=ca, common_name='second.example.com', created_by=user)

        certs = Certificate.objects.all()
        assert certs[0] == cert2  # Most recent first
        assert certs[1] == cert1


@pytest.mark.django_db
class TestCertificateEncryption:
    """Tests for Certificate private key encryption."""

    def test_set_and_get_private_key(self):
        """Test encrypting and decrypting certificate private key."""
        cert = CertificateFactory()
        test_key = '-----BEGIN RSA PRIVATE KEY-----\nTEST KEY\n-----END RSA PRIVATE KEY-----'

        cert.set_private_key(test_key)
        assert cert.private_key_pem_encrypted != ''
        assert cert.private_key_pem_encrypted != test_key

        decrypted = cert.get_private_key()
        assert decrypted == test_key

    def test_get_empty_private_key(self):
        """Test getting private key when none is set."""
        cert = CertificateFactory()
        cert.private_key_pem_encrypted = ''
        assert cert.get_private_key() == ''

    def test_has_private_key_property(self):
        """Test has_private_key property."""
        cert = CertificateFactory()
        cert.private_key_pem_encrypted = ''
        assert cert.has_private_key is False

        cert.private_key_pem_encrypted = 'encrypted_data'
        assert cert.has_private_key is True

    def test_set_private_key_without_encryption_key(self):
        """Test that setting private key fails without ENCRYPTION_KEY."""
        cert = CertificateFactory()

        with patch.object(settings, 'ENCRYPTION_KEY', None):
            with pytest.raises(ValueError, match="ENCRYPTION_KEY not configured"):
                cert.set_private_key('test key')


@pytest.mark.django_db
class TestCertificateExpiry:
    """Tests for Certificate expiry-related functionality."""

    def test_is_expired_true(self):
        """Test is_expired returns True for expired certificate."""
        cert = CertificateFactory()
        cert.not_after = timezone.now() - timedelta(days=1)
        assert cert.is_expired is True

    def test_is_expired_false(self):
        """Test is_expired returns False for valid certificate."""
        cert = CertificateFactory()
        cert.not_after = timezone.now() + timedelta(days=30)
        assert cert.is_expired is False

    def test_is_expired_no_date(self):
        """Test is_expired returns False when no expiry date."""
        cert = CertificateFactory()
        cert.not_after = None
        assert cert.is_expired is False

    def test_days_until_expiry(self):
        """Test days_until_expiry calculation."""
        from freezegun import freeze_time
        with freeze_time('2025-01-15 12:00:00'):
            cert = CertificateFactory()
            cert.not_after = timezone.now() + timedelta(days=45)
            assert cert.days_until_expiry == 45

    def test_days_until_expiry_expired(self):
        """Test days_until_expiry returns 0 for expired certificate."""
        cert = CertificateFactory()
        cert.not_after = timezone.now() - timedelta(days=10)
        assert cert.days_until_expiry == 0

    def test_days_until_expiry_no_date(self):
        """Test days_until_expiry returns None when no expiry date."""
        cert = CertificateFactory()
        cert.not_after = None
        assert cert.days_until_expiry is None

    def test_is_expiring_soon_true(self):
        """Test is_expiring_soon returns True within 30 days."""
        cert = CertificateFactory()
        cert.not_after = timezone.now() + timedelta(days=15)
        assert cert.is_expiring_soon is True

    def test_is_expiring_soon_false(self):
        """Test is_expiring_soon returns False beyond 30 days."""
        cert = CertificateFactory()
        cert.not_after = timezone.now() + timedelta(days=60)
        assert cert.is_expiring_soon is False


@pytest.mark.django_db
class TestCertificateRevocation:
    """Tests for Certificate revocation functionality."""

    def test_revoke_certificate(self):
        """Test revoking a certificate."""
        cert = CertificateFactory(status=CertificateStatus.ACTIVE)

        cert.revoke(reason=RevocationReason.KEY_COMPROMISE)

        assert cert.status == CertificateStatus.REVOKED
        assert cert.revoked_at is not None
        assert cert.revocation_reason == RevocationReason.KEY_COMPROMISE

    def test_revoke_certificate_default_reason(self):
        """Test revoking with default reason."""
        cert = CertificateFactory(status=CertificateStatus.ACTIVE)

        cert.revoke()

        assert cert.status == CertificateStatus.REVOKED
        assert cert.revocation_reason == RevocationReason.UNSPECIFIED


@pytest.mark.django_db
class TestCertificateArchive:
    """Tests for Certificate archive functionality."""

    def test_archive_revoked_certificate(self):
        """Test archiving a revoked certificate."""
        user = UserFactory()
        cert = RevokedCertificateFactory()

        cert.archive(user)

        assert cert.is_archived is True
        assert cert.archived_at is not None
        assert cert.archived_by == user

    def test_archive_active_certificate_fails(self):
        """Test archiving an active certificate raises error."""
        user = UserFactory()
        cert = CertificateFactory(status=CertificateStatus.ACTIVE)

        with pytest.raises(ValueError, match="Only revoked certificates can be archived"):
            cert.archive(user)

    def test_unarchive_certificate(self):
        """Test unarchiving a certificate."""
        user = UserFactory()
        cert = RevokedCertificateFactory()
        cert.archive(user)

        cert.unarchive()

        assert cert.is_archived is False
        assert cert.archived_at is None
        assert cert.archived_by is None


@pytest.mark.django_db
class TestCertificateRenewal:
    """Tests for Certificate renewal tracking."""

    def test_is_renewal_true(self):
        """Test is_renewal returns True when renewed_from is set."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)
        original = CertificateFactory(ca=ca, created_by=user)
        renewal = CertificateFactory(ca=ca, renewed_from=original, created_by=user)

        assert renewal.is_renewal is True
        assert original.is_renewal is False

    def test_has_been_renewed(self):
        """Test has_been_renewed property."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)
        original = CertificateFactory(ca=ca, created_by=user)

        assert original.has_been_renewed is False

        CertificateFactory(ca=ca, renewed_from=original, created_by=user)

        # Refresh from database
        original.refresh_from_db()
        assert original.has_been_renewed is True


@pytest.mark.django_db
class TestCertificateChain:
    """Tests for Certificate chain functionality."""

    def test_get_chain_pem(self):
        """Test get_chain_pem returns concatenated certificates."""
        user = UserFactory()
        root_ca = CertificateAuthorityFactory(
            ca_type='root',
            certificate_pem='ROOT CERT PEM',
            created_by=user,
        )
        intermediate_ca = CertificateAuthorityFactory(
            ca_type='intermediate',
            parent=root_ca,
            certificate_pem='INTERMEDIATE CERT PEM',
            created_by=user,
        )
        cert = CertificateFactory(
            ca=intermediate_ca,
            certificate_pem='END ENTITY CERT PEM',
            created_by=user,
        )

        chain = cert.get_chain_pem()

        assert 'END ENTITY CERT PEM' in chain
        assert 'INTERMEDIATE CERT PEM' in chain
        assert 'ROOT CERT PEM' in chain
